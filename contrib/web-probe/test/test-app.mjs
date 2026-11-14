// Deliberately weak test application, used only to exercise the web probe.
// Reflected input, loose cookie flags, missing security headers, an open
// redirect, and an XHR the probe should capture.
import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 8200);

const page = (body) => `<!doctype html>
<html><head><title>Test App</title>
<script src="/static/app.js"></script>
</head><body>
${body}
<form id="login" method="POST" action="/login">
  <input type="hidden" name="csrf" value="tok-123">
  <input type="text" name="username" autocomplete="on">
  <input type="password" name="password" autocomplete="on">
  <button type="submit">Sign in</button>
</form>
<form id="search" method="GET" action="/search">
  <input type="search" name="q">
</form>
</body></html>`;

createServer((request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${PORT}`);
  const send = (status, headers, body) => {
    response.writeHead(status, { "x-powered-by": "TestApp/0.1", ...headers });
    response.end(body);
  };

  if (url.pathname === "/") {
    return send(
      200,
      {
        "content-type": "text/html",
        // No Secure, no HttpOnly, no SameSite on the session cookie.
        "set-cookie": [
          "session=abc123; Path=/",
          "csrf=tok-123; Path=/; HttpOnly",
        ],
      },
      page("<h1>Test App</h1>"),
    );
  }
  if (url.pathname === "/static/app.js") {
    return send(
      200,
      { "content-type": "application/javascript" },
      'fetch("/api/me").then((r) => r.json()).then((d) => {\n' +
        '  document.title = "Test App - " + d.user;\n' +
        "});\n",
    );
  }
  if (url.pathname === "/api/me") {
    return send(
      200,
      { "content-type": "application/json" },
      JSON.stringify({ user: "guest", admin: false }),
    );
  }
  if (url.pathname === "/api/reflect") {
    // The exploitable CORS shape: echo whatever Origin arrives, with
    // credentials allowed.
    return send(
      200,
      {
        "content-type": "text/html",
        "access-control-allow-origin": request.headers.origin ?? "*",
        "access-control-allow-credentials": "true",
        vary: "Origin",
      },
      page("<h1>reflected</h1>"),
    );
  }
  if (url.pathname === "/api/fixed") {
    return send(
      200,
      {
        "content-type": "text/html",
        "access-control-allow-origin": "https://trusted.example",
      },
      page("<h1>fixed</h1>"),
    );
  }
  if (url.pathname === "/search") {
    // Reflected without escaping.
    const q = url.searchParams.get("q") ?? "";
    return send(
      200,
      { "content-type": "text/html" },
      page(`<p>Results for ${q}</p>`),
    );
  }
  if (url.pathname === "/go") {
    // Open redirect.
    return send(302, { location: url.searchParams.get("to") ?? "/" }, "");
  }
  if (url.pathname === "/login" && request.method === "POST") {
    const chunks = [];
    request.on("data", (part) => chunks.push(part));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      send(
        200,
        {
          "content-type": "text/html",
          "set-cookie": "session=loggedin; Path=/",
        },
        page(`<h1>Signed in</h1><pre id="echo">${body}</pre>`),
      );
    });
    return;
  }
  return send(404, { "content-type": "text/html" }, page("<h1>Not found</h1>"));
}).listen(PORT, "127.0.0.1", () =>
  console.error(`[testapp] listening on ${PORT}`),
);
