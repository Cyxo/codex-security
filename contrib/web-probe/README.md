# web-probe

Gives a Codex Security scan a browser. `web-probe` drives
[Lightpanda](https://lightpanda.io) over CDP and prints one JSON object per
action, so the scan agent can check how a deployed application behaves instead
of reasoning about the source alone.

Test only applications you are authorized to test. `--allow-host` pins the
reachable targets and Lightpanda's `--block-private-networks` keeps the browser
off internal addresses; both are controls the operator sets, not the agent.

## Why Lightpanda

Codex has browser features, but the CLI ships none of their implementation, so
a scan cannot use them. Driving a browser from the agent's shell works instead.
Lightpanda is a ~60 MB single binary with no Chrome dependency tree, it serves
CDP directly, and `--remote-allow-origins` plus `--block-private-networks`
bound what a remote client and the browser itself can reach.

## Install

Node 22.13+ and a Lightpanda binary:

```bash
curl -L -o lightpanda https://github.com/lightpanda-io/browser/releases/download/1.0.4/lightpanda-x86_64-linux
chmod +x lightpanda
./lightpanda serve --host 127.0.0.1 --port 9222
```

Linux x86_64 needs glibc 2.35+. In Docker, use the sidecar in
`compose.lightpanda.yaml` instead.

## Use

```bash
export WEB_PROBE_CDP=http://127.0.0.1:9222
node bin/web-probe.mjs audit http://localhost:3000/ --pretty
```

| Action                            | Reports                                                               |
| --------------------------------- | --------------------------------------------------------------------- |
| `audit URL`                       | One navigation, merged findings from all the checks below             |
| `visit URL`                       | Status, final URL, redirect chain, console errors, traffic            |
| `requests URL`                    | Every request and response, with headers and bodies                   |
| `headers URL`                     | Security headers on the main document                                 |
| `cookies URL`                     | Cookies and their `Secure`, `HttpOnly`, `SameSite` flags              |
| `forms URL`                       | Forms, fields, and how each submits                                   |
| `storage URL`                     | `localStorage` and `sessionStorage`, with secret-shaped keys flagged  |
| `fill URL --field n=v [--submit]` | What the browser sent, including hidden fields                        |
| `reflect URL --param q`           | Whether a parameter reaches the DOM unencoded, with context           |
| `cors URL --origin ORIGIN`        | Whether the service reflects a foreign `Origin`, and with credentials |
| `eval URL --expression JS`        | An expression's value in the page                                     |
| `screenshot URL --out f.png`      | A PNG                                                                 |

Reach authenticated pages with `--header 'Authorization: Bearer …'` or
`--cookie session=…`. `web-probe --help` lists every option.

### What the output means

`findings` **carries no severity, deliberately.** The checks see one response
from one route, so they cannot know what the application is, who reaches it,
what a session grants, or whether an injection sink exists. Those decide
severity, so the caller sets it. Codex Security already grades findings against
a rubric (`scan --rubric FILE`), and a second scale here would only anchor
whoever read it first.

Each finding carries the inputs for that judgement:

| Field         | Meaning                                                                                          |
| ------------- | ------------------------------------------------------------------------------------------------ |
| `observed`    | The fact, as seen on the wire or in the DOM                                                      |
| `basis`       | `direct` when the whole fact was observed, `heuristic` when part is inferred from a name pattern |
| `establishes` | What the fact settles on its own, sometimes "Nothing on its own"                                 |
| `assess`      | What the reader must determine before rating it                                                  |

So `cookie-not-httponly` reports that the attribute is absent and that script
on the origin can read the value, then asks what the cookie carries and whether
a sink exists. The session-like name match is named as a guess rather than
folded into a rating. `cors-wildcard-with-credentials` says outright that it
establishes nothing, because browsers refuse that pair.

`prompts/web-assessment.md` tells the agent to rate what it reports, and covers
blackbox, graybox, and whitebox audits. In the first two it says not to withhold
a finding for want of code; where source exists, naming the handler is an
addition, not a precondition.

## In a scan

Copy the prompt, set its authorized scope, and pass it to the scan:

```bash
cp contrib/web-probe/prompts/web-assessment.md ./input/context/
# Edit the scope list in that copy.

docker compose -f compose.runner.yaml -f compose.lightpanda.yaml \
  run --rm codex-security \
  scan /input/workspace \
  --scan-prompt-file /input/context/web-assessment.md \
  --output-dir /output/review --headless
```

`WEB_PROBE_TARGETS` is required by that overlay and becomes
`WEB_PROBE_ALLOWED_HOSTS` in the scanner, so the agent cannot navigate off the
targets you named. The browser, not the scanner, reaches the application: point
it at another Compose service by name, at `host.docker.internal`, or at a
public origin.

Custom validation is the other hook worth knowing: `--validation-prompt-file`
replaces a Standard scan's final validation step and inherits the scan
session's permissions, which is where dynamic confirmation of a candidate
belongs. Deep Scan workers run read-only and will not use the browser.

## Verify

```bash
WEB_PROBE_LIGHTPANDA=/path/to/lightpanda node test/run-tests.mjs
```

Eleven tests cover the analysis functions and the target guards and always run.
Seven more start `test/test-app.mjs`, a deliberately weak application, with a
real Lightpanda, and check that `audit` finds its missing CSP, plaintext
transport, and `HttpOnly`-less session cookie; that `visit` records a 302
chain; that `requests` captures an XHR's JSON body; that `fill --submit`
reports the POST body including the page's hidden CSRF field; that `cors`
separates a reflected `Origin` from a fixed one; and that `reflect` sees an
unescaped marker. Those seven skip when Lightpanda is absent.

Verified against Lightpanda 1.0.4 and 1.1.0-nightly.

## Lightpanda notes

Established by probing 1.0.4 and 1.1.0-nightly, since there is no published
compatibility matrix:

- Working: `Target.*`, `Page.navigate`, `Page.captureScreenshot`,
  `Runtime.evaluate`, `Network.enable` with `requestWillBeSent`,
  `responseReceived` and `loadingFinished`, `Network.getResponseBody`,
  `Network.getAllCookies`, `Network.setExtraHTTPHeaders`, `DOM.getDocument`,
  `DOM.querySelector`, `Emulation.setUserAgentOverride`.
- Absent: `Emulation.enable`, `Page.getResourceTree`.
- `Fetch.enable` works but pauses every request until the client continues it.
  This client leaves it off; enabling it without a continue handler hangs
  navigation. Request interception is therefore possible but unimplemented here.
- `--remote-allow-origins` defaults to rejecting any upgrade that **sends** an
  Origin header. `web-probe` sends none, so it connects without the flag; a
  browser-based client needs it.
