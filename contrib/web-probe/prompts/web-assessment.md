# Running web application

A Lightpanda browser is reachable over CDP, and `web-probe` drives it. Assess
the deployed application through it.

## Audit mode

<!-- Keep one line. -->

- **blackbox** — no source is supplied. Runtime evidence is the only evidence.
- **graybox** — part of the source is supplied. Use it where it reaches; fall
  back to runtime evidence everywhere else.
- **whitebox** — the full source is supplied alongside the running application.

In blackbox and graybox mode, **do not treat the absence of source as a reason
to withhold a finding, and do not ask for code**. A request and its response
are evidence in their own right. Where source is available, naming the handler
makes a finding easier to fix, so add it; it is never a precondition for
reporting.

## Scope

Only these targets are authorized:

<!-- Replace with the authorized origins, one per line. Delete this comment. -->

- http://localhost:3000

Do not navigate anywhere else. Do not attempt denial of service or modify or
destroy data. Everything below is read-only except `fill --submit`, which
submits a form you were asked to exercise.

## The tool

```bash
web-probe <action> <url> [options]        # one JSON object on stdout
web-probe --help                          # every action and option
```

`WEB_PROBE_CDP` already points at the browser. Add `--allow-host` to pin the
target, `--header 'Authorization: Bearer …'` or `--cookie session=…` to reach
authenticated pages.

| Action                                | Use it for                                                          |
| ------------------------------------- | ------------------------------------------------------------------- |
| `audit URL`                           | One pass: response, headers, cookies, forms, storage, merged checks |
| `visit URL`                           | Status, redirect chain, console errors, traffic summary             |
| `requests URL`                        | Every request and response with headers and bodies                  |
| `headers URL`                         | Security headers on the main document                               |
| `cookies URL`                         | Cookie flags                                                        |
| `forms URL`                           | Forms, fields, how each submits                                     |
| `storage URL`                         | localStorage and sessionStorage                                     |
| `fill URL --field n=v --submit`       | Submit a form, then read what was sent                              |
| `reflect URL --param q`               | Whether a parameter's value reaches the DOM unencoded               |
| `cors URL --origin https://evil.test` | Whether the service reflects a foreign Origin                       |
| `eval URL --expression JS`            | Page state the other actions do not cover                           |

## Suggested order

1. `audit` the entry point.
2. `forms` on each page that takes input, then `reflect` on the parameters
   those forms submit.
3. `requests` on the pages that matter, to map the backend routes the client
   calls and what they return. In blackbox mode this is your route inventory.
4. `cors` on any route that returns data for a signed-in user.
5. `fill --submit` on a form whose handler you are assessing, then read
   `submission.traffic` for the request actually sent, hidden fields included.
6. `cookies` and `storage` again after authenticating; both change at login.

## Reporting

The `findings` array in each result is the output of automated checks on one
navigation. **It carries no severity, by design.** The checks see one response
from one route: they cannot know what the application is, who reaches it, what
a session grants, or whether an injection sink exists, and those are what
decide severity. You decide it.

Each entry gives you the inputs instead:

- `observed` — the fact, as seen on the wire or in the DOM.
- `basis` — `direct` when the whole fact was observed, `heuristic` when part of
  it is inferred from a name pattern. Treat a `heuristic` entry as a lead to
  confirm, not a result.
- `establishes` — what the fact settles on its own. Some entries say
  "Nothing on its own"; those are not findings yet.
- `assess` — what you must determine before rating it.

**Rate every finding you report yourself**, from exploitability and impact in
_this_ application. If the scan was given a rubric, grade against it. Work from
what you can establish: who can reach the route, what the affected data or
action is worth, what an attacker gains, and what preconditions are needed. Say
which of those you verified and which you assumed.

Report a confirmed issue as a vulnerability, with the request and response that
demonstrate it and the steps to reproduce. Do not hedge an established finding
into an "indicator" or a "potential issue" because no source was read.

### Where runtime evidence is usually enough

Credentials or an `Authorization` header in cleartext; an authenticated
application served over HTTP; a session cookie readable by script or sent over
plaintext; a foreign `Origin` reflected with credentials on a response holding
per-caller data; a redirect whose destination comes from a parameter and leaves
your origins. For each, `assess` names the one thing still to check, usually
what the credential or response is worth.

### Where it is not

- `reflect` reporting `inDom: true` shows the input is reflected. Read
  `context` for the encoding actually applied, then establish whether the
  position permits script before calling it cross-site scripting. Reflected but
  correctly encoded is not a vulnerability. If you cannot establish it, report
  what you observed and say what remains unproven.
- `csrf-token-absent` is a question. Resubmit without the token and cross-site,
  and report that result.
- A missing `Content-Security-Policy`, `X-Content-Type-Options`,
  `Referrer-Policy`, or framing header is a hardening gap. Rate it as one. Do
  not promote it into an injection finding.
- A disclosed version needs an advisory that applies to it.

### Evidence to record

For each reported finding: the exact `web-probe` command, the request and
response that show the behaviour, and the reproduction steps. Where source is
available, add the handler. Keep the probe's own marker values and test
submissions out of the report except as reproduction detail.

If the browser is unreachable, say so and continue with whatever other evidence
you have, rather than guessing at runtime behaviour.
