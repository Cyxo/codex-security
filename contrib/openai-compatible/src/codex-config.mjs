// Persists the wrapper's provider into $CODEX_HOME/config.toml.
//
// Commands without a `--codex` option (classify-severity, suggest-owners,
// dedupe) read their provider from the ambient Codex configuration, so
// `--compat-write-config` puts it there. The block is marker-delimited and
// written at the top of the file: `model_provider` is a top-level key, and TOML
// binds top-level keys to the most recent table header.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const BEGIN = "# >>> cs-compat managed block >>>";
const END = "# <<< cs-compat managed block <<<";

export function codexHome(environment = process.env) {
  return environment.CODEX_HOME ?? join(homedir(), ".codex");
}

export function renderBlock({ providerId, baseUrl, envKey }) {
  return [
    BEGIN,
    "# Written by contrib/openai-compatible. Edits inside this block are lost.",
    `model_provider = ${JSON.stringify(providerId)}`,
    "",
    `[model_providers.${providerId}]`,
    'name = "OpenAI-compatible"',
    `base_url = ${JSON.stringify(baseUrl)}`,
    'wire_api = "responses"',
    `env_key = ${JSON.stringify(envKey)}`,
    END,
    "",
  ].join("\n");
}

export function stripBlock(contents) {
  const begin = contents.indexOf(BEGIN);
  if (begin === -1) return contents;
  const end = contents.indexOf(END, begin);
  if (end === -1) return contents.slice(0, begin);
  return (
    contents.slice(0, begin) +
    contents.slice(end + END.length).replace(/^\r?\n/, "")
  );
}

/** A second top-level `model_provider` would make the file invalid TOML. */
function conflictingKey(contents) {
  const beforeFirstTable = contents.split(/^\s*\[/m)[0];
  return /^\s*model_provider\s*=/m.test(beforeFirstTable);
}

export async function writeProviderConfig(
  { providerId, baseUrl, envKey },
  environment = process.env,
) {
  const home = codexHome(environment);
  const path = join(home, "config.toml");
  let existing = "";
  try {
    existing = await readFile(path, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const remainder = stripBlock(existing);
  if (conflictingKey(remainder)) {
    throw new Error(
      `${path} already sets a top-level model_provider. Remove it, or drop --compat-write-config ` +
        "and let the --codex overrides select the provider.",
    );
  }
  await mkdir(home, { recursive: true, mode: 0o700 });
  await writeFile(
    path,
    renderBlock({ providerId, baseUrl, envKey }) + remainder,
    {
      mode: 0o600,
    },
  );
  return path;
}
