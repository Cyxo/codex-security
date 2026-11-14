# Run Codex Security against any OpenAI-compatible API

`cs-compat` wraps the `codex-security` CLI so it can use an arbitrary
OpenAI-compatible endpoint. It probes the endpoint, starts a
Responses-to-Chat-Completions bridge only when the endpoint needs one, and
passes the resulting provider definition to `codex-security`.

## Why a bridge is needed

Codex Security drives the Codex executable bundled with `@openai/codex`
(0.167.1 in package 0.10.0). That executable speaks only the Responses API:

```
`wire_api = "chat"` is no longer supported.
How to fix: set `wire_api = "responses"` in your provider config.
```

The check runs while `config.toml` is parsed, so no provider setting reaches a
Chat Completions server. An endpoint that serves only `/v1/chat/completions`
therefore needs a translating proxy. This wrapper uses
[LiteLLM](https://docs.litellm.ai/docs/response_api_native_passthrough), which
already handles the shapes Codex sends: `namespace` tool containers, hoisted
`additional_tools`, and Responses-only request fields.

The endpoint URL itself was never hardcoded. `codex-security` forwards
`--codex model_providers.<id>.*` to Codex, and `sdk/typescript/src/config.ts`
defines its built-in OpenRouter, Fireworks, and Cheaper Inference providers the
same way. This wrapper exists for the endpoints those five `--provider` values
do not cover, and for the bridge.

## Install

Node.js 22.13+ and the `codex-security` CLI. For a Chat Completions backend,
also install LiteLLM:

```bash
pip install 'litellm[proxy]'
```

Point `CS_COMPAT_LITELLM` at the executable if it is not on `PATH`, for example
when it lives in a virtualenv.

## Use

```bash
export CS_COMPAT_BASE_URL=http://127.0.0.1:8000/v1
export CS_COMPAT_API_KEY=sk-local
node contrib/openai-compatible/bin/cs-compat.mjs scan . --model my-model
```

Probe the endpoint without running a scan:

```bash
node contrib/openai-compatible/bin/cs-compat.mjs --compat-detect scan .
```

```
base URL      http://127.0.0.1:8000/v1
  responses: no (404, route not served)
  chat/completions: yes (400, route served)
  models: my-model
=> chat
```

Detection posts an empty JSON body to each route, so it consumes no tokens: a
served route answers 400 or 422, an absent one answers 404 or 405. The result
decides the path.

| Endpoint serves | Wrapper does |
| --- | --- |
| `/responses` | Points Codex straight at the endpoint |
| `/chat/completions` only | Starts LiteLLM on a free loopback port and points Codex at it |
| both | Uses `/responses` directly |
| neither | Fails, reporting each probe |

Every argument that is not prefixed `--compat-` goes to `codex-security`
unchanged.

### Flags

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `--compat-base-url URL` | `CS_COMPAT_BASE_URL` | Endpoint base URL, including `/v1` |
| `--compat-api-key-env NAME` | `CS_COMPAT_API_KEY_ENV` | Variable holding the key (default `CS_COMPAT_API_KEY`) |
| `--compat-bridge MODE` | `CS_COMPAT_BRIDGE` | `auto`, `never`, or `always` |
| `--compat-bridge-impl NAME` | `CS_COMPAT_BRIDGE_IMPL` | `litellm` or `auto` |
| `--compat-bridge-port N` | | Bridge port, default a free one |
| `--compat-provider-id ID` | `CS_COMPAT_PROVIDER_ID` | Codex provider id, default `compat` |
| `--compat-cli PATH` | `CS_COMPAT_CLI` | `codex-security` executable |
| `--compat-write-config` | | Persist the provider into `$CODEX_HOME/config.toml` |
| `--compat-detect` | | Probe, print, exit |
| `--compat-dry-run` | | Print the `codex-security` invocation |
| `--compat-verbose` | | Report each decision |

The API key never appears on a command line. The wrapper exports it as
`CS_COMPAT_PROVIDER_KEY` and declares that name as the provider's `env_key`.
When a bridge runs, Codex receives a per-run LiteLLM master key instead, and the
upstream key reaches LiteLLM through its own environment variable.

### Commands that accept the overrides

`scan`, `scan-components`, `bulk-scan`, `validate`, `patch`, and `verify-fix`
parse `--codex KEY=VALUE`. Other model-using commands, among them
`classify-severity` and `suggest-owners`, read the ambient Codex configuration.
Run `--compat-write-config` once to serve those:

```bash
node contrib/openai-compatible/bin/cs-compat.mjs --compat-write-config --compat-detect scan .
```

It writes a marker-delimited block at the top of `$CODEX_HOME/config.toml`.
Top position is required: `model_provider` is a top-level key, and TOML binds a
top-level key to the table header above it. Rewriting replaces the block, and an
existing top-level `model_provider` outside the block stops the write rather
than producing invalid TOML. A bridge port changes between runs, so a persisted
bridge URL goes stale.

## Verify

```bash
node contrib/openai-compatible/test/run-tests.mjs
```

The suite starts two fake backends, one Chat Completions only and one Responses
only, and checks detection, routing, config writing, and the bridge. The last
test replays `test/fixtures/codex-responses-request.json`, a request captured
from Codex 0.167.1, through LiteLLM. It is skipped when LiteLLM is absent.

The fake Chat Completions backend rejects unknown top-level fields, which is how
`web_search_options` and `prompt_cache_key` were found leaking through the
bridge. `src/bridge.mjs` lists them in `additional_drop_params`. Add a field
there if a backend reports `Unrecognized request arguments`.

## Known limits

Codex sends a `namespace` tool container for its multi-agent tools. LiteLLM
flattens it to `multi_agent_v1__spawn_agent` and restores the inner name on the
way back, which the tests confirm at the wire level. Whether Codex rebinds that
name to its namespace is unverified; a mismatch would affect sub-agents and
Deep Scan workers, not a Standard scan.

Cost limits need published token rates. `--max-cost` and `estimateScanCost` have
no rates for a custom model, so leave them off.

Scans need Bubblewrap and unprivileged user namespaces, independent of the
provider. A container that lacks them fails in preflight:

```
Codex could not run a command in its sandbox: bwrap: Creating new namespace failed
```

`codex sandbox` has no other backend. Setting
`-c features.use_legacy_landlock=true` reaches a panic instead:
`filesystem-restricted execution requires bubblewrap to isolate app-server
sockets`. The host must supply the namespaces. See `docker/README.md` and
`compose.apparmor.yaml` in this repository.
