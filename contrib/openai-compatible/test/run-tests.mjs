#!/usr/bin/env node
// Checks the wrapper against fake OpenAI-compatible backends.
//
//   node test/run-tests.mjs
//
// The bridge tests need LiteLLM; point CS_COMPAT_LITELLM at it, or install it
// with `pip install 'litellm[proxy]'`. They are skipped when it is absent.

import { spawn } from "node:child_process";
import { readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { detectEndpoint, needsBridge, normalizeBaseUrl } from "../src/detect.mjs";
import { litellmConfig } from "../src/bridge.mjs";
import { renderBlock, stripBlock, writeProviderConfig } from "../src/codex-config.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const CHAT_PORT = 18111;
const RESPONSES_PORT = 18122;

let failures = 0;
let skipped = 0;

async function test(name, body) {
  try {
    await body();
    process.stdout.write(`ok   ${name}\n`);
  } catch (error) {
    failures += 1;
    process.stdout.write(`FAIL ${name}\n     ${error.message.split("\n").join("\n     ")}\n`);
  }
}

function skip(name, reason) {
  skipped += 1;
  process.stdout.write(`skip ${name} (${reason})\n`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}: expected ${expected}, got ${actual}`);
}

function startServer(script, env) {
  const child = spawn(process.execPath, [join(here, script)], {
    stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env, ...env },
  });
  return new Promise((resolve, reject) => {
    const onData = (chunk) => {
      if (chunk.toString("utf8").includes("listening")) {
        child.stderr.off("data", onData);
        resolve(child);
      }
    };
    child.stderr.on("data", onData);
    child.once("error", reject);
    setTimeout(() => reject(new Error(`${script} did not start`)), 10_000);
  });
}

async function run(args, env = {}) {
  const child = spawn(process.execPath, [join(here, "..", "bin", "cs-compat.mjs"), ...args], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const code = await new Promise((resolve) => child.on("exit", resolve));
  return { code, stdout, stderr };
}

async function litellmAvailable() {
  const executable = process.env.CS_COMPAT_LITELLM ?? "litellm";
  return await new Promise((resolve) => {
    const child = spawn(executable, ["--version"], { stdio: "ignore" });
    child.on("error", () => resolve(false));
    child.on("exit", (code) => resolve(code === 0));
  });
}

const chat = await startServer("fake-chat-backend.mjs", { PORT: String(CHAT_PORT), STRICT: "1" });
const responses = await startServer("fake-responses-backend.mjs", { PORT: String(RESPONSES_PORT) });
const chatUrl = `http://127.0.0.1:${CHAT_PORT}/v1`;
const responsesUrl = `http://127.0.0.1:${RESPONSES_PORT}/v1`;

try {
  await test("normalizeBaseUrl strips trailing slashes and rejects junk", () => {
    assertEqual(normalizeBaseUrl("http://x/v1/"), "http://x/v1", "trailing slash");
    let threw = false;
    try {
      normalizeBaseUrl("ftp://x/v1");
    } catch {
      threw = true;
    }
    assert(threw, "a non-http scheme should be rejected");
  });

  await test("detects a chat-completions-only endpoint", async () => {
    const detection = await detectEndpoint(chatUrl, "sk-test");
    assertEqual(detection.kind, "chat", "kind");
    assert(needsBridge(detection), "a chat-only endpoint needs the bridge");
    assert(detection.models.includes("fake-chat-model"), "models should be listed");
  });

  await test("detects a responses-native endpoint", async () => {
    const detection = await detectEndpoint(responsesUrl, "sk-test");
    assertEqual(detection.kind, "responses", "kind");
    assert(!needsBridge(detection), "a responses endpoint needs no bridge");
  });

  await test("reports an unreachable endpoint", async () => {
    const detection = await detectEndpoint("http://127.0.0.1:1/v1", "sk-test");
    assertEqual(detection.kind, "none", "kind");
  });

  await test("--compat-detect exits 0 for a usable endpoint and 1 otherwise", async () => {
    const usable = await run(["--compat-detect", "scan", "."], { CS_COMPAT_BASE_URL: chatUrl });
    assertEqual(usable.code, 0, "chat endpoint exit code");
    assert(usable.stdout.includes("=> chat"), `expected kind in output, got: ${usable.stdout}`);
    const dead = await run(["--compat-detect", "scan", "."], {
      CS_COMPAT_BASE_URL: "http://127.0.0.1:1/v1",
    });
    assertEqual(dead.code, 1, "unreachable endpoint exit code");
  });

  await test("a responses endpoint is used directly, with no bridge", async () => {
    const result = await run(["--compat-dry-run", "scan", ".", "--model", "m"], {
      CS_COMPAT_BASE_URL: responsesUrl,
      CS_COMPAT_API_KEY: "sk-test",
    });
    assertEqual(result.code, 0, `exit code (stderr: ${result.stderr})`);
    assert(
      result.stdout.includes("model_providers.compat.base_url") && result.stdout.includes(responsesUrl),
      `should point at the endpoint itself, got: ${result.stdout}`,
    );
    assert(!result.stderr.includes("starting"), "no bridge should start");
  });

  await test("--compat-bridge=never refuses a chat-only endpoint", async () => {
    const result = await run(["--compat-bridge", "never", "scan", "."], {
      CS_COMPAT_BASE_URL: chatUrl,
      CS_COMPAT_API_KEY: "sk-test",
    });
    assertEqual(result.code, 1, "exit code");
    assert(result.stderr.includes("--compat-bridge=never"), `unexpected error: ${result.stderr}`);
  });

  await test("commands without --codex do not receive overrides", async () => {
    const result = await run(["--compat-dry-run", "info"], { CS_COMPAT_BASE_URL: responsesUrl });
    assertEqual(result.code, 0, `exit code (stderr: ${result.stderr})`);
    assert(!result.stdout.includes("--codex"), `info must not get --codex: ${result.stdout}`);
  });

  await test("the managed config block round-trips and refuses a conflict", async () => {
    const home = await mkdtemp(join(tmpdir(), "cs-compat-test-"));
    try {
      const block = renderBlock({ providerId: "compat", baseUrl: "http://x/v1", envKey: "K" });
      assertEqual(stripBlock(`${block}model = "m"\n`), 'model = "m"\n', "stripBlock");

      await writeFile(join(home, "config.toml"), '[tui]\nnotifications = true\n');
      const path = await writeProviderConfig(
        { providerId: "compat", baseUrl: "http://x/v1", envKey: "K" },
        { CODEX_HOME: home },
      );
      const written = await readFile(path, "utf8");
      assert(written.startsWith("# >>> cs-compat"), "the block must come first");
      assert(written.includes("[tui]"), "existing settings must survive");
      assert(
        written.indexOf("model_provider") < written.indexOf("["),
        "model_provider must precede every table header",
      );

      // Rewriting replaces the block instead of appending a second one.
      await writeProviderConfig(
        { providerId: "compat", baseUrl: "http://y/v1", envKey: "K" },
        { CODEX_HOME: home },
      );
      const rewritten = await readFile(path, "utf8");
      assertEqual(rewritten.split("[model_providers.compat]").length - 1, 1, "provider table count");
      assert(rewritten.includes("http://y/v1"), "the new base URL should be written");

      await writeFile(join(home, "config.toml"), 'model_provider = "mine"\n');
      let threw = false;
      try {
        await writeProviderConfig(
          { providerId: "compat", baseUrl: "http://x/v1", envKey: "K" },
          { CODEX_HOME: home },
        );
      } catch {
        threw = true;
      }
      assert(threw, "an existing top-level model_provider must be refused");
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await test("the LiteLLM config forces the chat bridge and drops Codex-only fields", () => {
    const config = litellmConfig(chatUrl);
    assert(config.includes("model: openai/chat_completions/*"), "bridge prefix missing");
    assert(config.includes("- web_search_options"), "web_search_options must be dropped");
    assert(config.includes("- prompt_cache_key"), "prompt_cache_key must be dropped");
    assert(!config.includes("sk-"), "no literal key belongs in the config file");
  });

  if (await litellmAvailable()) {
    await test("a real Codex request bridges to chat completions and streams back", async () => {
      const { startBridge } = await import("../src/bridge.mjs");
      const bridge = await startBridge({
        targetBaseUrl: chatUrl,
        apiKey: "sk-test",
        port: 0,
      });
      try {
        const body = JSON.parse(
          await readFile(join(here, "fixtures", "codex-responses-request.json"), "utf8"),
        );
        body.model = "fake-chat-model";
        const response = await fetch(`${bridge.baseUrl}/responses`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "text/event-stream",
            authorization: `Bearer ${bridge.apiKey}`,
          },
          body: JSON.stringify(body),
        });
        const text = await response.text();
        assertEqual(response.status, 200, `bridge status (${text.slice(0, 400)})`);
        for (const expected of [
          "response.created",
          "response.output_item.added",
          "response.function_call_arguments.done",
          "response.completed",
        ]) {
          assert(text.includes(`"type":"${expected}"`), `missing SSE event ${expected}`);
        }
        assert(text.includes('"name":"exec_command"'), "the tool call should reach the client");
      } finally {
        await bridge.stop();
      }
    });
  } else {
    skip("a real Codex request bridges to chat completions and streams back", "litellm not installed");
  }
} finally {
  chat.kill();
  responses.kill();
}

process.stdout.write(`\n${failures === 0 ? "PASS" : "FAIL"} (${failures} failed, ${skipped} skipped)\n`);
process.exitCode = failures === 0 ? 0 : 1;
