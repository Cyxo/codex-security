// Turns captured traffic into findings.
//
// Each finding names what was observed and how far that observation goes. Some
// are settled by runtime evidence alone, such as credentials posted over HTTP;
// others, such as a reflected marker or an absent CSRF field, mark a question
// for the caller to close. Severities are chosen with that difference in mind,
// so a reviewer reading only this output does not overstate a hardening gap.

const SESSION_COOKIE = /sess|sid|auth|token|jwt|login|remember/i;
const CSRF_FIELD = /csrf|xsrf|_token|authenticity|nonce|state/i;
const SECRET_KEY =
  /token|secret|key|password|passwd|jwt|bearer|credential|session/i;

function finding(id, severity, title, detail, evidence) {
  return {
    id,
    severity,
    title,
    detail,
    ...(evidence === undefined ? {} : { evidence }),
  };
}

/** @param {{url: string, headers: Record<string,string>, status: number|undefined}} document */
export function analyzeHeaders(document) {
  const headers = document.headers ?? {};
  const https = document.url?.startsWith("https://") === true;
  const findings = [];
  const get = (name) => headers[name];

  const csp = get("content-security-policy");
  if (csp === undefined) {
    findings.push(
      finding(
        "csp-missing",
        "medium",
        "No Content-Security-Policy",
        "The document sets no CSP, so injected script is not constrained by policy.",
      ),
    );
  } else {
    const unsafe = ["'unsafe-inline'", "'unsafe-eval'"].filter((token) =>
      csp.includes(token),
    );
    if (unsafe.length > 0) {
      findings.push(
        finding(
          "csp-unsafe-directives",
          "low",
          `CSP allows ${unsafe.join(" and ")}`,
          "These tokens remove most of the protection a CSP gives against injected script.",
          csp,
        ),
      );
    }
    if (/(?:default|script)-src[^;]*\*/.test(csp)) {
      findings.push(
        finding(
          "csp-wildcard-source",
          "low",
          "CSP uses a wildcard script source",
          "A wildcard source lets any host serve script.",
          csp,
        ),
      );
    }
    if (!/frame-ancestors/.test(csp) && get("x-frame-options") === undefined) {
      findings.push(
        finding(
          "framing-unrestricted",
          "low",
          "Neither frame-ancestors nor X-Frame-Options is set",
          "The document can be framed by any origin, which enables clickjacking against its controls.",
        ),
      );
    }
  }

  if (csp === undefined && get("x-frame-options") === undefined) {
    findings.push(
      finding(
        "framing-unrestricted",
        "low",
        "No X-Frame-Options and no CSP",
        "The document can be framed by any origin, which enables clickjacking against its controls.",
      ),
    );
  }

  if (https && get("strict-transport-security") === undefined) {
    findings.push(
      finding(
        "hsts-missing",
        "medium",
        "No Strict-Transport-Security",
        "An HTTPS response without HSTS leaves the first request downgradable.",
      ),
    );
  } else if (https) {
    const maxAge = /max-age=(\d+)/.exec(get("strict-transport-security") ?? "");
    if (maxAge !== null && Number(maxAge[1]) < 15_552_000) {
      findings.push(
        finding(
          "hsts-short",
          "low",
          "HSTS max-age is below six months",
          "A short max-age narrows the window the protection covers.",
          get("strict-transport-security"),
        ),
      );
    }
  }

  if (!https && document.url !== undefined) {
    findings.push(
      finding(
        "plaintext-transport",
        "high",
        "The document was served over HTTP",
        "Credentials, cookies, and responses travel in cleartext.",
        document.url,
      ),
    );
  }

  if (get("x-content-type-options") !== "nosniff") {
    findings.push(
      finding(
        "nosniff-missing",
        "low",
        "No X-Content-Type-Options: nosniff",
        "Browsers may sniff a response's type and treat data as script.",
      ),
    );
  }

  if (get("referrer-policy") === undefined) {
    findings.push(
      finding(
        "referrer-policy-missing",
        "informational",
        "No Referrer-Policy",
        "Full URLs, including any identifiers in a path or query, may leak to third parties.",
      ),
    );
  }

  const allowOrigin = get("access-control-allow-origin");
  if (
    allowOrigin === "*" &&
    get("access-control-allow-credentials") === "true"
  ) {
    findings.push(
      finding(
        "cors-wildcard-with-credentials",
        "low",
        "CORS sends a wildcard origin alongside credentials",
        "Browsers reject this pair, so a credentialed cross-origin read is blocked and the combination is not exploitable as it stands. It does show the service means to allow credentialed cross-origin access, so check whether another route reflects the request's Origin instead: run `web-probe cors`.",
      ),
    );
  } else if (allowOrigin === "*") {
    findings.push(
      finding(
        "cors-wildcard",
        "informational",
        "CORS allows any origin",
        "Without credentials this exposes only what an unauthenticated caller could fetch anyway. Confirm the response carries no data specific to the caller.",
        allowOrigin,
      ),
    );
  }

  for (const name of [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
  ]) {
    const value = get(name);
    if (value !== undefined) {
      findings.push(
        finding(
          "version-disclosure",
          "informational",
          `${name} discloses software`,
          "A version string tells an attacker which advisories to try.",
          `${name}: ${value}`,
        ),
      );
    }
  }

  return findings;
}

/** @param {{name: string, secure: boolean, httpOnly: boolean, sameSite: string|undefined}[]} cookies */
export function analyzeCookies(cookies, { https }) {
  const findings = [];
  for (const cookie of cookies) {
    const sessionLike = SESSION_COOKIE.test(cookie.name);
    if (https && cookie.secure !== true) {
      findings.push(
        finding(
          "cookie-not-secure",
          sessionLike ? "high" : "medium",
          `Cookie ${cookie.name} lacks Secure`,
          "The cookie can be sent over a plaintext connection.",
          cookie.name,
        ),
      );
    }
    if (sessionLike && cookie.httpOnly !== true) {
      findings.push(
        finding(
          "cookie-not-httponly",
          "high",
          `Session cookie ${cookie.name} lacks HttpOnly`,
          "Injected script can read the cookie and take over the session.",
          cookie.name,
        ),
      );
    }
    if (cookie.sameSite === undefined || cookie.sameSite === "None") {
      findings.push(
        finding(
          "cookie-samesite",
          sessionLike ? "medium" : "low",
          `Cookie ${cookie.name} has ${cookie.sameSite === undefined ? "no SameSite" : "SameSite=None"}`,
          "The cookie rides on cross-site requests, which is the precondition for CSRF.",
          cookie.name,
        ),
      );
    }
    if (cookie.domain?.startsWith(".") === true) {
      findings.push(
        finding(
          "cookie-broad-domain",
          "low",
          `Cookie ${cookie.name} is scoped to ${cookie.domain}`,
          "Every subdomain receives the cookie, including any that is less trusted.",
          cookie.domain,
        ),
      );
    }
  }
  return findings;
}

/** Collected in the page, so it reflects the DOM after script has run. */
export const FORM_SNIPPET = `(() => {
  const forms = [...document.querySelectorAll("form")].map((form, index) => ({
    index,
    id: form.id || null,
    name: form.getAttribute("name") || null,
    method: (form.getAttribute("method") || "GET").toUpperCase(),
    action: form.action || null,
    enctype: form.enctype || null,
    target: form.getAttribute("target") || null,
    autocomplete: form.getAttribute("autocomplete") || null,
    fields: [...form.querySelectorAll("input,select,textarea")].map((field) => ({
      name: field.getAttribute("name") || null,
      type: (field.getAttribute("type") || field.tagName.toLowerCase()).toLowerCase(),
      autocomplete: field.getAttribute("autocomplete") || null,
      required: field.hasAttribute("required"),
      hidden: field.getAttribute("type") === "hidden",
    })),
  }));
  return forms;
})()`;

export function analyzeForms(forms, { https, pageUrl }) {
  const findings = [];
  for (const form of forms) {
    const label = form.id ?? form.name ?? `form[${form.index}]`;
    const fields = form.fields ?? [];
    const hasPassword = fields.some((field) => field.type === "password");
    const actionHttps = form.action?.startsWith("https://") === true;

    if (hasPassword && form.method === "GET") {
      findings.push(
        finding(
          "password-in-query",
          "high",
          `${label} submits a password with GET`,
          "The password lands in the URL, so it reaches logs, history, and referrers.",
          form.action,
        ),
      );
    }
    if (hasPassword && !actionHttps && form.action !== null) {
      findings.push(
        finding(
          "credentials-over-http",
          "high",
          `${label} posts credentials to a non-HTTPS action`,
          "Credentials travel in cleartext.",
          form.action,
        ),
      );
    }
    if (https && form.action !== null && !actionHttps) {
      findings.push(
        finding(
          "mixed-form-action",
          "medium",
          `${label} on an HTTPS page submits to ${form.action}`,
          "The submission leaves the secure origin.",
          form.action,
        ),
      );
    }
    if (
      form.method === "POST" &&
      !fields.some((field) => CSRF_FIELD.test(field.name ?? ""))
    ) {
      findings.push(
        finding(
          "csrf-token-absent",
          "medium",
          `${label} posts without a token-shaped field`,
          "No field name matches the usual CSRF token names. The application may rely on SameSite cookies or a header instead; confirm which.",
          fields
            .map((field) => field.name)
            .filter(Boolean)
            .join(", "),
        ),
      );
    }
    for (const field of fields) {
      if (
        field.type === "password" &&
        field.autocomplete !== "new-password" &&
        field.autocomplete !== "off"
      ) {
        findings.push(
          finding(
            "password-autocomplete",
            "informational",
            `${label} password field allows autocomplete`,
            "Shared-device browsers may store the value.",
            field.name ?? "(unnamed)",
          ),
        );
      }
    }
  }
  return findings;
}

export const STORAGE_SNIPPET = `(() => {
  const dump = (store) => {
    const out = {};
    for (let i = 0; i < store.length; i += 1) {
      const key = store.key(i);
      out[key] = store.getItem(key);
    }
    return out;
  };
  return { localStorage: dump(localStorage), sessionStorage: dump(sessionStorage) };
})()`;

export function analyzeStorage(storage) {
  const findings = [];
  for (const [area, entries] of Object.entries(storage ?? {})) {
    for (const [key, value] of Object.entries(entries ?? {})) {
      if (SECRET_KEY.test(key)) {
        findings.push(
          finding(
            "secret-in-web-storage",
            "medium",
            `${area} holds a key named ${key}`,
            "Web storage is readable by any script on the origin, so an injection reads it. Confirm whether the value is a credential.",
            `${key} = ${String(value).slice(0, 40)}${String(value).length > 40 ? "…" : ""}`,
          ),
        );
      }
    }
  }
  return findings;
}

/** Third-party hosts and plaintext subresources in the captured traffic. */
export function analyzeTraffic(requests, { pageUrl }) {
  const findings = [];
  const pageHost = URL.parse(pageUrl ?? "")?.host;
  const https = pageUrl?.startsWith("https://") === true;
  const thirdParty = new Set();
  for (const entry of requests) {
    const parsed = URL.parse(entry.url ?? "");
    if (parsed === null) continue;
    if (https && parsed.protocol === "http:") {
      findings.push(
        finding(
          "mixed-content",
          "medium",
          `Plaintext subresource ${parsed.host}`,
          "An HTTPS page loaded this over HTTP, so it can be read and altered in transit.",
          entry.url,
        ),
      );
    }
    if (pageHost !== undefined && parsed.host !== pageHost)
      thirdParty.add(parsed.host);
    const auth = entry.requestHeaders?.authorization;
    if (auth !== undefined && parsed.protocol === "http:") {
      findings.push(
        finding(
          "auth-header-over-http",
          "high",
          `Authorization header sent in cleartext to ${parsed.host}`,
          "The credential is readable on the wire.",
          entry.url,
        ),
      );
    }
  }
  if (thirdParty.size > 0) {
    findings.push(
      finding(
        "third-party-hosts",
        "informational",
        `${thirdParty.size} third-party host(s) contacted`,
        "Each one is code or data the application trusts at runtime.",
        [...thirdParty].join(", "),
      ),
    );
  }
  return findings;
}

/**
 * Assess what a foreign Origin header got back. Reflection plus credentials is
 * the exploitable shape: the browser then lets the attacker's page read an
 * authenticated response. A wildcard is not, because browsers refuse to pair
 * it with credentials.
 */
export function analyzeCors({
  sentOrigin,
  allowOrigin,
  allowCredentials,
  allowOriginVaries,
}) {
  const findings = [];
  const credentials = allowCredentials === "true";
  const reflected = allowOrigin === sentOrigin;

  if (reflected && credentials) {
    findings.push(
      finding(
        "cors-origin-reflected-with-credentials",
        "high",
        "The service reflects an arbitrary Origin and allows credentials",
        "Any site a victim visits can read this response with the victim's session. Confirm the response body carries data worth reading.",
        `Origin: ${sentOrigin} -> Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: true`,
      ),
    );
  } else if (reflected) {
    findings.push(
      finding(
        "cors-origin-reflected",
        "low",
        "The service reflects an arbitrary Origin without credentials",
        "A cross-origin read is possible but unauthenticated, so it exposes only what any caller could fetch. It becomes high severity if credentials are ever allowed on this route.",
        `Origin: ${sentOrigin} -> Access-Control-Allow-Origin: ${allowOrigin}`,
      ),
    );
  }
  if (
    !reflected &&
    allowOrigin !== undefined &&
    allowOrigin !== "*" &&
    !allowOriginVaries
  ) {
    findings.push(
      finding(
        "cors-allow-origin-static",
        "informational",
        `Access-Control-Allow-Origin is fixed at ${allowOrigin}`,
        "The foreign origin was not echoed, so this route does not reflect. Check that the allowed origin is one you control.",
        allowOrigin,
      ),
    );
  }
  return findings;
}

export const SEVERITY_ORDER = ["high", "medium", "low", "informational"];

export function sortFindings(findings) {
  const seen = new Set();
  return findings
    .filter((item) => {
      const key = `${item.id}|${item.evidence ?? ""}|${item.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort(
      (left, right) =>
        SEVERITY_ORDER.indexOf(left.severity) -
        SEVERITY_ORDER.indexOf(right.severity),
    );
}
