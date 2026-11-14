#!/usr/bin/env node
// Exercises web-probe against the deliberately weak test application.
//
//   node test/run-tests.mjs
//
// Needs a Lightpanda binary. Point WEB_PROBE_LIGHTPANDA at it, or put
// `lightpanda` on PATH. Every test is skipped when it is absent, since the
// analysis functions are covered separately below.

import { spawn } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  analyzeCookies,
  analyzeForms,
  analyzeHeaders,
  analyzeStorage,
  analyzeTraffic,
  sortFindings,
} from "../src/analyze.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const APP_PORT = 18200;
const CDP_PORT = 19222;
const APP = `http://127.0.0.1:${APP_PORT}`;
const CDP = `http://127.0.0.1:${CDP_PORT}`;

let failures = 0;
let skipped = 0;

async function test(name, body) {
  try {
    await body();
    process.stdout.write(`ok   ${name}\n`);
  } catch (error) {
    failures += 1;
    process.stdout.write(
      `FAIL ${name}\n     ${error.message.split("\n").join("\n     ")}\n`,
    );
  }
}

function skip(name, reason) {
  skipped += 1;
  process.stdout.write(`skip ${name} (${reason})\n`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function ids(findings) {
  return new Set(findings.map((item) => item.id));
}

function probe(args) {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [join(here, "..", "bin", "web-probe.mjs"), ...args],
      {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, WEB_PROBE_CDP: CDP },
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("exit", (code) => {
      let json;
      try {
        json = JSON.parse(stdout);
      } catch {
        json = undefined;
      }
      resolve({ code, json, stdout, stderr });
    });
  });
}

async function waitFor(check, label, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`${label} did not become ready`);
}

function lightpandaAvailable() {
  const executable = process.env.WEB_PROBE_LIGHTPANDA ?? "lightpanda";
  return new Promise((resolve) => {
    const child = spawn(executable, ["version"], { stdio: "ignore" });
    child.on("error", () => resolve(false));
    child.on("exit", (code) => resolve(code === 0));
  });
}

// ---------------------------------------------------------------- unit tests

await test("header analysis flags a missing CSP and a disclosed version", () => {
  const findings = analyzeHeaders({
    url: "https://app.test/",
    headers: {
      "x-powered-by": "Express",
      "strict-transport-security": "max-age=31536000",
    },
    status: 200,
  });
  const found = ids(findings);
  assert(found.has("csp-missing"), "csp-missing expected");
  assert(found.has("version-disclosure"), "version-disclosure expected");
  assert(
    !found.has("hsts-missing"),
    "HSTS is present, so it must not be reported",
  );
  assert(!found.has("plaintext-transport"), "an https URL is not plaintext");
});

await test("header analysis treats HTTP as high severity", () => {
  const findings = analyzeHeaders({
    url: "http://app.test/",
    headers: {},
    status: 200,
  });
  const plaintext = findings.find((item) => item.id === "plaintext-transport");
  assert(plaintext !== undefined, "plaintext-transport expected");
  assert(
    plaintext.severity === "high",
    `expected high, got ${plaintext.severity}`,
  );
});

await test("CORS wildcard with credentials outranks a plain wildcard", () => {
  const withCredentials = analyzeHeaders({
    url: "https://app.test/",
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
    },
    status: 200,
  });
  assert(
    ids(withCredentials).has("cors-wildcard-with-credentials"),
    "credentialed wildcard expected",
  );
  assert(
    !ids(withCredentials).has("cors-wildcard"),
    "the weaker finding must not also fire",
  );
});

await test("cookie analysis separates session cookies from the rest", () => {
  const findings = analyzeCookies(
    [
      { name: "session", secure: false, httpOnly: false, sameSite: undefined },
      { name: "theme", secure: true, httpOnly: false, sameSite: "Lax" },
    ],
    { https: true },
  );
  const session = findings.filter((item) => item.evidence === "session");
  assert(
    session.some(
      (item) => item.id === "cookie-not-httponly" && item.severity === "high",
    ),
    "session HttpOnly expected high",
  );
  assert(
    session.some((item) => item.id === "cookie-not-secure"),
    "session Secure expected",
  );
  assert(
    !findings.some(
      (item) => item.evidence === "theme" && item.id === "cookie-not-secure",
    ),
    "a Secure cookie must not be flagged",
  );
});

await test("form analysis spots a password sent with GET and a token-shaped field", () => {
  const withToken = analyzeForms(
    [
      {
        index: 0,
        id: "login",
        method: "POST",
        action: "https://app.test/login",
        fields: [
          { name: "csrf", type: "hidden" },
          { name: "password", type: "password", autocomplete: "off" },
        ],
      },
    ],
    { https: true, pageUrl: "https://app.test/" },
  );
  assert(
    !ids(withToken).has("csrf-token-absent"),
    "a csrf field must satisfy the check",
  );

  const getPassword = analyzeForms(
    [
      {
        index: 0,
        id: "weak",
        method: "GET",
        action: "http://app.test/login",
        fields: [{ name: "password", type: "password" }],
      },
    ],
    { https: true, pageUrl: "https://app.test/" },
  );
  const found = ids(getPassword);
  assert(found.has("password-in-query"), "password-in-query expected");
  assert(found.has("credentials-over-http"), "credentials-over-http expected");
  assert(
    found.has("csrf-token-absent") === false,
    "a GET form is not a CSRF sink",
  );
});

await test("storage analysis flags secret-shaped keys only", () => {
  const findings = analyzeStorage({
    localStorage: { authToken: "abc", theme: "dark" },
    sessionStorage: {},
  });
  assert(findings.length === 1, `expected one finding, got ${findings.length}`);
  assert(findings[0].title.includes("authToken"), "authToken expected");
});

await test("traffic analysis reports mixed content and third-party hosts", () => {
  const findings = analyzeTraffic(
    [
      { url: "https://app.test/", requestHeaders: {} },
      { url: "http://cdn.other/x.js", requestHeaders: {} },
      {
        url: "http://api.other/v1",
        requestHeaders: { authorization: "Bearer x" },
      },
    ],
    { pageUrl: "https://app.test/" },
  );
  const found = ids(findings);
  assert(found.has("mixed-content"), "mixed-content expected");
  assert(found.has("auth-header-over-http"), "auth-header-over-http expected");
  assert(found.has("third-party-hosts"), "third-party-hosts expected");
});

await test("findings sort by severity and drop duplicates", () => {
  const sorted = sortFindings([
    { id: "a", severity: "low", title: "x" },
    { id: "b", severity: "high", title: "y" },
    { id: "a", severity: "low", title: "x" },
  ]);
  assert(sorted.length === 2, `expected 2, got ${sorted.length}`);
  assert(sorted[0].severity === "high", "high must come first");
});

await test("an unsupported scheme is refused before the browser starts", async () => {
  const result = await probe(["visit", "file:///etc/passwd"]);
  assert(result.code === 1, "exit code");
  assert(
    result.stderr.includes("Only http and https"),
    `unexpected error: ${result.stderr}`,
  );
});

await test("a target outside the allow list is refused", async () => {
  const result = await probe([
    "visit",
    "http://example.com/",
    "--allow-host",
    "127.0.0.1",
  ]);
  assert(result.code === 1, "exit code");
  assert(
    result.stderr.includes("not in the allowed target list"),
    `unexpected error: ${result.stderr}`,
  );
});

// ------------------------------------------------------- browser-backed tests

if (!(await lightpandaAvailable())) {
  for (const name of [
    "audit reports the test application's weaknesses",
    "visit records the redirect chain",
    "requests captures an XHR body",
    "fill submits a form and captures the post data",
    "reflect reports an unescaped marker",
  ]) {
    skip(name, "lightpanda not available");
  }
} else {
  const app = spawn(process.execPath, [join(here, "test-app.mjs")], {
    stdio: ["ignore", "ignore", "ignore"],
    env: { ...process.env, PORT: String(APP_PORT) },
  });
  const browser = spawn(
    process.env.WEB_PROBE_LIGHTPANDA ?? "lightpanda",
    [
      "serve",
      "--host",
      "127.0.0.1",
      "--port",
      String(CDP_PORT),
      "--log-level",
      "error",
    ],
    { stdio: ["ignore", "ignore", "ignore"] },
  );
  const reachable = (url) =>
    fetch(url, { signal: AbortSignal.timeout(1000) }).then(
      (response) => response.ok,
      () => false,
    );
  try {
    await waitFor(() => reachable(`${APP}/`), "the test application");
    await waitFor(() => reachable(`${CDP}/json/version`), "lightpanda");

    await test("audit reports the test application's weaknesses", async () => {
      const result = await probe(["audit", `${APP}/`]);
      assert(result.code === 0, `exit ${result.code}: ${result.stderr}`);
      const found = ids(result.json.findings);
      for (const expected of [
        "plaintext-transport",
        "cookie-not-httponly",
        "credentials-over-http",
        "csp-missing",
        "version-disclosure",
      ]) {
        assert(
          found.has(expected),
          `expected ${expected}, got ${[...found].join(", ")}`,
        );
      }
      assert(
        result.json.forms.length === 2,
        `expected 2 forms, got ${result.json.forms.length}`,
      );
      assert(
        result.json.cookies.length === 2,
        `expected 2 cookies, got ${result.json.cookies.length}`,
      );
      // The login form carries a hidden csrf field, so the check must stay quiet.
      assert(
        !found.has("csrf-token-absent"),
        "csrf-token-absent must not fire on the login form",
      );
    });

    await test("visit records the redirect chain", async () => {
      const result = await probe([
        "visit",
        `${APP}/go?to=${encodeURIComponent(`${APP}/search?q=hi`)}`,
      ]);
      assert(result.code === 0, `exit ${result.code}: ${result.stderr}`);
      assert(
        result.json.redirects.length === 1,
        `expected 1 redirect, got ${JSON.stringify(result.json.redirects)}`,
      );
      assert(result.json.redirects[0].status === 302, "expected a 302");
      assert(
        result.json.finalUrl.endsWith("/search?q=hi"),
        `unexpected final URL ${result.json.finalUrl}`,
      );
    });

    await test("requests captures an XHR body", async () => {
      const result = await probe(["requests", `${APP}/`]);
      assert(result.code === 0, `exit ${result.code}: ${result.stderr}`);
      const xhr = result.json.traffic.find((entry) =>
        entry.url.endsWith("/api/me"),
      );
      assert(
        xhr !== undefined,
        `no /api/me request in ${result.json.traffic.map((e) => e.url).join(", ")}`,
      );
      assert(
        xhr.body.includes('"user":"guest"'),
        `unexpected body ${xhr.body}`,
      );
      assert(
        xhr.responseHeaders["content-type"] === "application/json",
        "content type expected",
      );
    });

    await test("fill submits a form and captures the post data", async () => {
      const result = await probe([
        "fill",
        `${APP}/`,
        "--form",
        "#login",
        "--field",
        "username=admin",
        "--field",
        "password=hunter2",
        "--submit",
      ]);
      assert(result.code === 0, `exit ${result.code}: ${result.stderr}`);
      assert(
        result.json.missing.length === 0,
        `unfilled fields: ${result.json.missing}`,
      );
      const post = result.json.submission.traffic.find(
        (entry) => entry.method === "POST",
      );
      assert(post !== undefined, "no POST captured");
      assert(
        post.postData.includes("username=admin"),
        `unexpected post data ${post.postData}`,
      );
      // The hidden token the page supplied must ride along untouched.
      assert(
        post.postData.includes("csrf=tok-123"),
        "the hidden csrf field should be submitted",
      );
    });

    await test("reflect reports an unescaped marker", async () => {
      const result = await probe(["reflect", `${APP}/search`, "--param", "q"]);
      assert(result.code === 0, `exit ${result.code}: ${result.stderr}`);
      assert(result.json.inDom === true, "the marker should reach the DOM");
      assert(
        result.json.inResponseBody === true,
        "the marker should appear in the raw body",
      );
      assert(
        result.json.context.includes(result.json.marker),
        "the context should show the marker",
      );
    });
  } finally {
    app.kill();
    browser.kill();
  }
}

process.stdout.write(
  `\n${failures === 0 ? "PASS" : "FAIL"} (${failures} failed, ${skipped} skipped)\n`,
);
process.exitCode = failures === 0 ? 0 : 1;
