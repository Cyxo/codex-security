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
navigation. It is your starting point, not your report. Decide on each entry,
then report what survives.

**Report a confirmed issue as a vulnerability**, with a severity, the request
and response that demonstrate it, and the steps to reproduce. Do not hedge an
established finding into an "indicator" or a "potential issue" because no
source was read.

### Settled by runtime evidence alone

Observing these is enough. Report them as vulnerabilities:

- Credentials submitted over HTTP, or an `Authorization` header sent in
  cleartext.
- An authenticated application served over HTTP.
- A session cookie without `HttpOnly`, or without `Secure` on an HTTPS origin.
  Severity reflects that these amplify an injection rather than being
  exploitable alone; report them regardless.
- A foreign `Origin` reflected with `Access-Control-Allow-Credentials: true`,
  per `cors`, when the response carries data specific to the caller. Check the
  body: reflection on a response with nothing worth reading is not the same
  finding. A wildcard `Access-Control-Allow-Origin` paired with credentials is
  **not** this: browsers refuse that pair, so it is a misconfiguration to note,
  not an exploitable one.
- A redirect whose destination comes from a request parameter and leaves the
  application's origins, per the `redirects` chain.
- A plaintext subresource on an HTTPS page.

### Needs a second step before you call it a vulnerability

- `reflect` reporting `inDom: true` shows the input is reflected. Read
  `context` for the encoding actually applied, then establish whether the
  position permits script before calling it cross-site scripting. Reflected
  but correctly encoded is not a vulnerability. If you cannot establish it,
  report what you observed and say what remains unproven.
- `csrf-token-absent` is a question, not an answer. The route may be protected
  by `SameSite` cookies or a required header. Resubmit without the token, or
  with the cookie but no token, and report the result.
- Missing `Content-Security-Policy`, `X-Content-Type-Options`,
  `Referrer-Policy`, or framing protection are hardening gaps. Report them as
  such, at their own severity. Do not promote them into an injection finding.
- A disclosed version is informational until you tie it to an advisory
  affecting that version.

### Evidence to record

For each reported finding: the exact `web-probe` command, the request and
response that show the behaviour, and the reproduction steps. Where source is
available, add the handler. Keep the probe's own marker values and test
submissions out of the report except as reproduction detail.

If the browser is unreachable, say so and continue with whatever other evidence
you have, rather than guessing at runtime behaviour.
