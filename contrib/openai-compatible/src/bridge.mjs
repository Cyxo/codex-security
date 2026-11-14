// Starts and stops the Responses-to-Chat-Completions bridge.
//
// LiteLLM is the only implementation: it already carries the Codex-specific
// handling this needs — flattening `namespace` tools, hoisting
// `additional_tools`, and dropping Responses-only request fields that a
// Chat Completions backend rejects.

import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TARGET_KEY_VARIABLE = "CS_COMPAT_TARGET_KEY";
const STARTUP_TIMEOUT_MS = 120_000;
const HEALTH_INTERVAL_MS = 500;

/**
 * Responses-only fields Codex sends on every turn. LiteLLM's `drop_params`
 * keeps them for models it has no capability record for, and a strict backend
 * answers `Unrecognized request arguments`.
 */
const DROPPED_REQUEST_FIELDS = [
  "web_search_options",
  "prompt_cache_key",
  "client_metadata",
  "safety_identifier",
];

export const BRIDGE_IMPLEMENTATIONS = { litellm: startLitellm };

export async function startBridge({ implementation = "auto", ...options }) {
  const name = implementation === "auto" ? "litellm" : implementation;
  const start = BRIDGE_IMPLEMENTATIONS[name];
  if (start === undefined) {
    throw new Error(
      `Unknown bridge implementation '${name}'. Available: ${Object.keys(BRIDGE_IMPLEMENTATIONS).join(", ")}.`,
    );
  }
  return { implementation: name, ...(await start(options)) };
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

export function litellmConfig(targetBaseUrl) {
  return [
    "model_list:",
    '  - model_name: "*"',
    "    litellm_params:",
    // The `openai/chat_completions/` prefix forces the bridge; without it a
    // deployment on the `openai` provider posts to the backend's /responses.
    "      model: openai/chat_completions/*",
    `      api_base: ${JSON.stringify(targetBaseUrl)}`,
    `      api_key: os.environ/${TARGET_KEY_VARIABLE}`,
    "      drop_params: true",
    "      additional_drop_params:",
    ...DROPPED_REQUEST_FIELDS.map((field) => `        - ${field}`),
    "",
    "litellm_settings:",
    "  drop_params: true",
    "",
    "general_settings:",
    "  master_key: os.environ/LITELLM_MASTER_KEY",
    "",
  ].join("\n");
}

async function waitForHealth(baseUrl, child, deadline) {
  let lastError = "no response";
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`The bridge exited with status ${child.exitCode} before becoming ready.`);
    }
    try {
      const response = await fetch(`${baseUrl}/health/liveliness`, {
        signal: AbortSignal.timeout(HEALTH_INTERVAL_MS * 4),
      });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, HEALTH_INTERVAL_MS));
  }
  throw new Error(`The bridge did not become ready within ${STARTUP_TIMEOUT_MS / 1000}s (${lastError}).`);
}

async function startLitellm({ targetBaseUrl, apiKey, port, log = () => {} }) {
  const executable = process.env.CS_COMPAT_LITELLM ?? "litellm";
  const chosenPort = port > 0 ? port : await freePort();
  const masterKey = `sk-cs-compat-${randomBytes(24).toString("hex")}`;
  const directory = await mkdtemp(join(tmpdir(), "cs-compat-"));
  const configPath = join(directory, "config.yaml");
  await writeFile(configPath, litellmConfig(targetBaseUrl), { mode: 0o600 });

  log(`starting ${executable} on 127.0.0.1:${chosenPort} -> ${targetBaseUrl}`);
  const child = spawn(
    executable,
    ["--config", configPath, "--host", "127.0.0.1", "--port", String(chosenPort), "--num_workers", "1"],
    {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        LITELLM_MASTER_KEY: masterKey,
        // An endpoint without authentication still needs a non-empty value.
        [TARGET_KEY_VARIABLE]: apiKey || "none",
      },
    },
  );
  const output = [];
  const record = (chunk) => {
    output.push(chunk.toString("utf8"));
    if (output.length > 200) output.shift();
  };
  child.stdout.on("data", record);
  child.stderr.on("data", record);

  const baseUrl = `http://127.0.0.1:${chosenPort}`;
  const stop = async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => child.once("exit", resolve)),
        new Promise((resolve) => setTimeout(resolve, 5000)),
      ]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
    await rm(directory, { recursive: true, force: true });
  };

  try {
    await new Promise((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", (error) =>
        reject(
          error.code === "ENOENT"
            ? new Error(
                `Could not run '${executable}'. Install it with \`pip install 'litellm[proxy]'\`, ` +
                  "or point CS_COMPAT_LITELLM at the executable.",
              )
            : error,
        ),
      );
    });
    await waitForHealth(baseUrl, child, Date.now() + STARTUP_TIMEOUT_MS);
  } catch (error) {
    await stop();
    const tail = output.join("").trim().split("\n").slice(-15).join("\n");
    throw new Error(`${error.message}${tail ? `\n--- bridge output ---\n${tail}` : ""}`);
  }

  return { baseUrl: `${baseUrl}/v1`, apiKey: masterKey, stop };
}
