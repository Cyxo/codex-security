#!/usr/bin/env node
// Runs codex-security against any OpenAI-compatible endpoint.
//
// Codex 0.167 removed `wire_api = "chat"`, so an endpoint that serves only
// `/chat/completions` needs a translating bridge. This wrapper probes the
// endpoint, starts a bridge only when one is needed, and hands codex-security
// the matching `--codex model_providers.*` overrides.
//
// Wrapper flags are prefixed `--compat-` and are removed from the arguments
// forwarded to codex-security.

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import {
  detectEndpoint,
  describeDetection,
  needsBridge,
} from "../src/detect.mjs";
import { startBridge, BRIDGE_IMPLEMENTATIONS } from "../src/bridge.mjs";
import { writeProviderConfig } from "../src/codex-config.mjs";

/** Subcommands whose parser accepts `--codex KEY=VALUE`. */
const CODEX_OVERRIDE_COMMANDS = new Set([
  "scan",
  "scan-components",
  "bulk-scan",
  "validate",
  "patch",
  "verify-fix",
]);

/** Name of the environment variable Codex reads the provider key from. */
const PROVIDER_KEY_VARIABLE = "CS_COMPAT_PROVIDER_KEY";

const FLAGS = {
  "--compat-base-url": "baseUrl",
  "--compat-api-key-env": "apiKeyEnv",
  "--compat-bridge": "bridge",
  "--compat-bridge-impl": "bridgeImpl",
  "--compat-bridge-port": "bridgePort",
  "--compat-provider-id": "providerId",
  "--compat-cli": "cli",
};
const BOOLEAN_FLAGS = {
  "--compat-detect": "detectOnly",
  "--compat-dry-run": "dryRun",
  "--compat-write-config": "writeConfig",
  "--compat-verbose": "verbose",
  "--compat-help": "help",
};

const USAGE = `cs-compat - run codex-security against any OpenAI-compatible API

Usage:
  cs-compat [wrapper flags] <codex-security command> [command args]

Wrapper flags:
  --compat-base-url URL     Endpoint base URL, including /v1 (env CS_COMPAT_BASE_URL)
  --compat-api-key-env NAME Environment variable holding the key (env CS_COMPAT_API_KEY_ENV,
                            default CS_COMPAT_API_KEY)
  --compat-bridge MODE      auto | never | always (env CS_COMPAT_BRIDGE, default auto)
  --compat-bridge-impl NAME ${Object.keys(BRIDGE_IMPLEMENTATIONS).join(" | ")} | auto
                            (env CS_COMPAT_BRIDGE_IMPL, default auto)
  --compat-bridge-port N    Bridge port (default: a free port)
  --compat-provider-id ID   Codex provider id to define (default: compat)
  --compat-cli PATH         codex-security executable (env CS_COMPAT_CLI)
  --compat-write-config     Also persist the provider into $CODEX_HOME/config.toml
  --compat-detect           Probe the endpoint, print the result, and exit
  --compat-dry-run          Print the codex-security invocation without running it
  --compat-verbose          Report what the wrapper decides
  --compat-help             Show this message

Example:
  export CS_COMPAT_BASE_URL=http://127.0.0.1:8000/v1
  export CS_COMPAT_API_KEY=sk-local
  cs-compat scan . --model my-model
`;

function parseArguments(argv) {
  const options = {};
  const forwarded = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (Object.hasOwn(BOOLEAN_FLAGS, argument)) {
      options[BOOLEAN_FLAGS[argument]] = true;
      continue;
    }
    const [name, inlineValue] = argument.includes("=")
      ? [
          argument.slice(0, argument.indexOf("=")),
          argument.slice(argument.indexOf("=") + 1),
        ]
      : [argument, undefined];
    if (Object.hasOwn(FLAGS, name)) {
      const value = inlineValue ?? argv[(index += 1)];
      if (value === undefined) throw new Error(`${name} requires a value.`);
      options[FLAGS[name]] = value;
      continue;
    }
    forwarded.push(argument);
  }
  return { options, forwarded };
}

/** The first argument that is not a flag names the subcommand. */
function subcommandOf(forwarded) {
  return forwarded.find((argument) => !argument.startsWith("-"));
}

function resolveCli(explicit) {
  const candidate = explicit ?? process.env.CS_COMPAT_CLI;
  if (candidate) return candidate;
  const require = createRequire(import.meta.url);
  try {
    return require
      .resolve("@openai/codex-security/package.json")
      .replace(/package\.json$/, "bin/codex-security.mjs");
  } catch {
    return "codex-security";
  }
}

function providerOverrides(providerId, baseUrl) {
  return [
    `model_provider='${providerId}'`,
    `model_providers.${providerId}.name='OpenAI-compatible'`,
    `model_providers.${providerId}.base_url='${baseUrl}'`,
    `model_providers.${providerId}.wire_api='responses'`,
    `model_providers.${providerId}.env_key='${PROVIDER_KEY_VARIABLE}'`,
  ].flatMap((override) => ["--codex", override]);
}

async function main() {
  const { options, forwarded } = parseArguments(process.argv.slice(2));
  if (options.help || forwarded.length === 0) {
    process.stdout.write(USAGE);
    return 0;
  }

  const log = (message) => {
    if (options.verbose || options.detectOnly || options.dryRun) {
      process.stderr.write(`cs-compat: ${message}\n`);
    }
  };

  const baseUrl = options.baseUrl ?? process.env.CS_COMPAT_BASE_URL;
  if (!baseUrl) {
    throw new Error(
      "Set CS_COMPAT_BASE_URL or pass --compat-base-url with the endpoint base URL (including /v1).",
    );
  }
  const apiKeyEnv =
    options.apiKeyEnv ??
    process.env.CS_COMPAT_API_KEY_ENV ??
    "CS_COMPAT_API_KEY";
  const apiKey = process.env[apiKeyEnv] ?? "";
  if (apiKey === "") {
    log(`no key in ${apiKeyEnv}; probing without authentication`);
  }

  const detection = await detectEndpoint(baseUrl, apiKey);
  if (options.detectOnly) {
    process.stdout.write(
      `${describeDetection(detection)}\n=> ${detection.kind}\n`,
    );
    return detection.kind === "none" ? 1 : 0;
  }
  log(`endpoint kind: ${detection.kind}`);
  if (detection.kind === "none") {
    throw new Error(
      `No usable endpoint at ${detection.baseUrl}.\n${describeDetection(detection)}\n` +
        "Check the URL (it usually ends in /v1), the API key, and that the server is reachable.",
    );
  }

  const bridgeMode = options.bridge ?? process.env.CS_COMPAT_BRIDGE ?? "auto";
  if (!["auto", "never", "always"].includes(bridgeMode)) {
    throw new Error(
      `--compat-bridge must be auto, never, or always (got ${bridgeMode}).`,
    );
  }
  const useBridge =
    bridgeMode === "always" ||
    (bridgeMode === "auto" && needsBridge(detection));
  if (!useBridge && detection.kind === "chat") {
    throw new Error(
      `${detection.baseUrl} serves only /chat/completions, which Codex 0.167 cannot use, ` +
        "and --compat-bridge=never forbids starting a bridge.",
    );
  }

  const providerId =
    options.providerId ?? process.env.CS_COMPAT_PROVIDER_ID ?? "compat";
  const subcommand = subcommandOf(forwarded);
  let bridge;
  try {
    let providerBaseUrl = detection.baseUrl;
    if (useBridge) {
      bridge = await startBridge({
        implementation:
          options.bridgeImpl ?? process.env.CS_COMPAT_BRIDGE_IMPL ?? "auto",
        targetBaseUrl: detection.baseUrl,
        apiKey,
        port: options.bridgePort === undefined ? 0 : Number(options.bridgePort),
        log,
      });
      providerBaseUrl = bridge.baseUrl;
      log(`bridge ${bridge.implementation} serving ${providerBaseUrl}`);
    }

    if (options.writeConfig) {
      const path = await writeProviderConfig({
        providerId,
        baseUrl: providerBaseUrl,
        envKey: PROVIDER_KEY_VARIABLE,
      });
      log(`wrote provider '${providerId}' into ${path}`);
    }

    const supportsOverrides = CODEX_OVERRIDE_COMMANDS.has(subcommand);
    if (!supportsOverrides) {
      log(
        `'${subcommand}' does not accept --codex; relying on $CODEX_HOME/config.toml ` +
          "(use --compat-write-config to populate it)",
      );
    }
    const args = supportsOverrides
      ? [...forwarded, ...providerOverrides(providerId, providerBaseUrl)]
      : [...forwarded];

    const cli = resolveCli(options.cli);
    if (options.dryRun) {
      process.stdout.write(
        `${PROVIDER_KEY_VARIABLE}=<${apiKeyEnv}> ${cli} ${args.map(quote).join(" ")}\n`,
      );
      return 0;
    }
    return await run(cli, args, {
      ...process.env,
      [PROVIDER_KEY_VARIABLE]: bridge?.apiKey ?? apiKey,
    });
  } finally {
    await bridge?.stop();
  }
}

function quote(argument) {
  return /[\s'"$]/.test(argument)
    ? `'${argument.replaceAll("'", "'\\''")}'`
    : argument;
}

function run(cli, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(cli, args, { stdio: "inherit", env });
    const forward = (signal) => () => child.kill(signal);
    const handlers = ["SIGINT", "SIGTERM"].map((signal) => {
      const handler = forward(signal);
      process.on(signal, handler);
      return [signal, handler];
    });
    const detach = () => {
      for (const [signal, handler] of handlers) process.off(signal, handler);
    };
    child.on("error", (error) => {
      detach();
      reject(error);
    });
    child.on("exit", (code, signal) => {
      detach();
      resolve(signal ? 128 + 15 : (code ?? 1));
    });
  });
}

try {
  process.exitCode = await main();
} catch (error) {
  process.stderr.write(
    `cs-compat: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}
