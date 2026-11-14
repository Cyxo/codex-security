# Running web application

A Lightpanda browser is reachable over CDP, and `web-probe` drives it. Use it
to check how the deployed application behaves, alongside reading the source.

## Scope

Only these targets are authorized:

<!-- Replace with the authorized origins, one per line. Delete this comment. -->

- http://localhost:3000

Do not navigate anywhere else. Do not attempt authentication bypass, denial of
service, or data modification. Every action below is read-only reconnaissance
except `fill --submit`, which submits a form you were told to submit.

## The tool

```bash
web-probe <action> <url> [options]        # one JSON object on stdout
web-probe --help                          # every action and option
```

`WEB_PROBE_CDP` already points at the browser. Add `--allow-host` to pin the
target, `--header 'Authorization: Bearer …'` or `--cookie session=…` to reach
authenticated pages.

| Action                          | Use it for                                                            |
| ------------------------------- | --------------------------------------------------------------------- |
| `audit URL`                     | One pass: response, headers, cookies, forms, storage, merged findings |
| `visit URL`                     | Status, redirect chain, console errors, traffic summary               |
| `requests URL`                  | Every request and response with headers and bodies                    |
| `headers URL`                   | Security headers on the main document                                 |
| `cookies URL`                   | Cookie flags                                                          |
| `forms URL`                     | Forms, fields, how each submits                                       |
| `storage URL`                   | localStorage and sessionStorage                                       |
| `fill URL --field n=v --submit` | Submit a form, then read what was sent                                |
| `reflect URL --param q`         | Whether a parameter's value reaches the DOM unencoded                 |
| `eval URL --expression JS`      | Read page state the other actions do not cover                        |

## Suggested order

1. `audit` the entry point. It gives the broadest picture for one navigation.
2. `forms` on each page that takes input, then `reflect` on the parameters
   those forms submit.
3. `requests` on the pages that matter, to see which backend routes the client
   calls and what they return. Compare that list against the routes you found
   in the source; a route the client reaches that the source review missed is
   worth following.
4. `fill --submit` on a form whose handler you are assessing, then read
   `submission.traffic` for the request the browser actually sent, including
   hidden fields and headers.
5. `cookies` and `storage` after authenticating, since both change at login.

## Reading the output

`findings` are **indicators, not confirmed vulnerabilities**. Each one names
what was observed. Before reporting any of them:

- Tie it to the code that produces it. A missing header is a finding about a
  specific response from a specific handler, not about the repository.
- Decide whether it is reachable and whether it matters for this application.
  A missing CSP on a static error page is not the same as on an authenticated
  page that renders user input.
- For `reflect`, read `context` to see the encoding actually applied. A marker
  in the DOM is not proof of script injection; it tells you where to look.
- Drop anything the application legitimately does. Say so in the report rather
  than leaving it unexplained.

Record the exact command and the response evidence for every finding you keep.
If the browser is unreachable, say so and continue with the source review
rather than guessing at runtime behaviour.
