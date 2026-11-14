// Turns captured traffic into findings.
//
// Deliberately no severity. This module sees one response from one route: it
// cannot know what the application is, who reaches it, what a session grants,
// or whether an injection sink exists, and those decide severity. A number
// here would only anchor whoever reads it. Codex Security already grades
// findings against a rubric (`scan --rubric`), so the caller rates them.
//
// Each finding carries instead:
//   observed     the fact, as seen on the wire or in the DOM
//   basis        "direct" when the whole fact was observed, "heuristic" when
//                part of it is inferred from a name pattern
//   establishes  what the fact settles on its own
//   assess       what the reader must determine before rating it

const SESSION_COOKIE = /sess|sid|auth|token|jwt|login|remember/i;
const CSRF_FIELD = /csrf|xsrf|_token|authenticity|nonce|state/i;
const SECRET_KEY =
  /token|secret|key|password|passwd|jwt|bearer|credential|session/i;

function finding({
  id,
  title,
  observed,
  basis,
  establishes,
  assess,
  evidence,
}) {
  return {
    id,
    title,
    observed,
    basis,
    establishes,
    assess,
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
      finding({
        id: "csp-missing",
        title: "No Content-Security-Policy",
        observed:
          "The document response carries no Content-Security-Policy header.",
        basis: "direct",
        establishes:
          "No policy constrains where script on this document may come from.",
        assess:
          "Whether any route renders untrusted input into this origin, and what a successful injection would reach. Without a sink this is a hardening gap; with one it decides whether the injection runs.",
      }),
    );
  } else {
    const unsafe = ["'unsafe-inline'", "'unsafe-eval'"].filter((token) =>
      csp.includes(token),
    );
    if (unsafe.length > 0) {
      findings.push(
        finding({
          id: "csp-unsafe-directives",
          title: `CSP allows ${unsafe.join(" and ")}`,
          observed: `The policy contains ${unsafe.join(" and ")}.`,
          basis: "direct",
          establishes:
            "The policy does not stop injected inline script or eval.",
          assess:
            "Whether an injection sink exists on this origin, and what the policy still blocks.",
          evidence: csp,
        }),
      );
    }
    if (/(?:default|script)-src[^;]*\*/.test(csp)) {
      findings.push(
        finding({
          id: "csp-wildcard-source",
          title: "CSP uses a wildcard script source",
          observed:
            "A default-src or script-src directive includes a wildcard.",
          basis: "direct",
          establishes: "Any host may serve script to this document.",
          assess:
            "Whether an attacker can get script onto a host the wildcard covers.",
          evidence: csp,
        }),
      );
    }
    if (!/frame-ancestors/.test(csp) && get("x-frame-options") === undefined) {
      findings.push(
        framingFinding(
          "The policy sets no frame-ancestors and there is no X-Frame-Options header.",
        ),
      );
    }
  }

  if (csp === undefined && get("x-frame-options") === undefined) {
    findings.push(
      framingFinding(
        "The document response carries neither a CSP nor an X-Frame-Options header.",
      ),
    );
  }

  if (https && get("strict-transport-security") === undefined) {
    findings.push(
      finding({
        id: "hsts-missing",
        title: "No Strict-Transport-Security",
        observed:
          "An HTTPS response carries no Strict-Transport-Security header.",
        basis: "direct",
        establishes:
          "A browser that has not pinned this origin may be talked into a plaintext first request.",
        assess:
          "Whether users reach the origin by typing it or following a plaintext link, and whether it is in the preload list.",
      }),
    );
  } else if (https) {
    const maxAge = /max-age=(\d+)/.exec(get("strict-transport-security") ?? "");
    if (maxAge !== null && Number(maxAge[1]) < 15_552_000) {
      findings.push(
        finding({
          id: "hsts-short",
          title: "HSTS max-age is below six months",
          observed: `max-age is ${maxAge[1]} seconds.`,
          basis: "direct",
          establishes: "The pin expires sooner than the usual baseline.",
          assess:
            "Whether the shorter window is deliberate, such as during a rollout.",
          evidence: get("strict-transport-security"),
        }),
      );
    }
  }

  if (!https && document.url !== undefined) {
    findings.push(
      finding({
        id: "plaintext-transport",
        title: "The document was served over HTTP",
        observed: `The document was fetched from ${document.url}.`,
        basis: "direct",
        establishes:
          "Everything in this request and response is readable and alterable in transit.",
        assess:
          "Whether this is the deployment users reach, and what crosses it. A local development server is not a finding; a production login page is.",
        evidence: document.url,
      }),
    );
  }

  if (get("x-content-type-options") !== "nosniff") {
    findings.push(
      finding({
        id: "nosniff-missing",
        title: "No X-Content-Type-Options: nosniff",
        observed: "The document response does not set nosniff.",
        basis: "direct",
        establishes:
          "A browser may sniff a response's type rather than trust the declared one.",
        assess:
          "Whether any route returns caller-controlled bytes with a type a browser could sniff into script.",
      }),
    );
  }

  if (get("referrer-policy") === undefined) {
    findings.push(
      finding({
        id: "referrer-policy-missing",
        title: "No Referrer-Policy",
        observed: "The document response sets no Referrer-Policy.",
        basis: "direct",
        establishes:
          "The browser default decides how much of this URL reaches other origins.",
        assess:
          "Whether URLs on this origin carry identifiers or tokens in their path or query.",
      }),
    );
  }

  const allowOrigin = get("access-control-allow-origin");
  if (
    allowOrigin === "*" &&
    get("access-control-allow-credentials") === "true"
  ) {
    findings.push(
      finding({
        id: "cors-wildcard-with-credentials",
        title: "CORS sends a wildcard origin alongside credentials",
        observed:
          "Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true.",
        basis: "direct",
        establishes:
          "Nothing on its own: browsers refuse that pair, so a credentialed cross-origin read of this response is blocked.",
        assess:
          "Whether another route reflects the request's Origin instead, which is the exploitable shape. Run `web-probe cors` against the routes returning per-caller data.",
      }),
    );
  } else if (allowOrigin === "*") {
    findings.push(
      finding({
        id: "cors-wildcard",
        title: "CORS allows any origin",
        observed:
          "Access-Control-Allow-Origin is *, with no credentials allowed.",
        basis: "direct",
        establishes:
          "Any origin may read this response, but only as an unauthenticated caller.",
        assess:
          "Whether the response carries anything an unauthenticated caller could not already fetch directly.",
        evidence: allowOrigin,
      }),
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
        finding({
          id: "version-disclosure",
          title: `${name} discloses software`,
          observed: `${name}: ${value}`,
          basis: "direct",
          establishes:
            "The response names the software, and sometimes its version.",
          assess:
            "Whether the named version has advisories that apply to this deployment. Absent that, this is reconnaissance detail rather than a weakness.",
          evidence: `${name}: ${value}`,
        }),
      );
    }
  }

  return findings;
}

function framingFinding(observed) {
  return finding({
    id: "framing-unrestricted",
    title: "Framing is unrestricted",
    observed,
    basis: "direct",
    establishes: "Any origin may embed this document in a frame.",
    assess:
      "Whether the page carries a control whose single click changes state, which is what makes framing worth abusing.",
  });
}

/** @param {{name: string, secure: boolean, httpOnly: boolean, sameSite: string|undefined}[]} cookies */
export function analyzeCookies(cookies, { https }) {
  const findings = [];
  for (const cookie of cookies) {
    // The missing attribute is observed. Whether the cookie carries a session
    // is inferred from its name, so that part stays in `assess`.
    const sessionLike = SESSION_COOKIE.test(cookie.name);
    const whatItCarries = sessionLike
      ? "What the cookie carries: its name matches a session-like pattern, which is a guess, not an observation."
      : "What the cookie carries.";

    if (https && cookie.secure !== true) {
      findings.push(
        finding({
          id: "cookie-not-secure",
          title: `Cookie ${cookie.name} lacks Secure`,
          observed: "The cookie has no Secure attribute, on an HTTPS origin.",
          basis: "direct",
          establishes:
            "The browser will send this cookie over a plaintext connection to the same host.",
          assess: `${whatItCarries} Whether any plaintext request to this host is reachable.`,
          evidence: cookie.name,
        }),
      );
    }
    if (cookie.httpOnly !== true) {
      findings.push(
        finding({
          id: "cookie-not-httponly",
          title: `Cookie ${cookie.name} is readable by script`,
          observed: "The cookie has no HttpOnly attribute.",
          basis: "direct",
          establishes:
            "Any script running on this origin can read the cookie's value.",
          assess: `${whatItCarries} Whether an injection sink exists on this origin, since that is what turns a readable cookie into a takeover.`,
          evidence: cookie.name,
        }),
      );
    }
    if (cookie.sameSite === undefined || cookie.sameSite === "None") {
      findings.push(
        finding({
          id: "cookie-samesite",
          title: `Cookie ${cookie.name} has ${cookie.sameSite === undefined ? "no SameSite" : "SameSite=None"}`,
          observed:
            cookie.sameSite === undefined
              ? "The cookie sets no SameSite attribute, so the browser default applies."
              : "The cookie sets SameSite=None.",
          basis: "direct",
          establishes:
            "The cookie may accompany requests the user did not initiate from this site.",
          assess: `${whatItCarries} Whether any state-changing route relies on this cookie alone, which is what a cross-site request would exploit.`,
          evidence: cookie.name,
        }),
      );
    }
    if (cookie.domain?.startsWith(".") === true) {
      findings.push(
        finding({
          id: "cookie-broad-domain",
          title: `Cookie ${cookie.name} is scoped to ${cookie.domain}`,
          observed: `The cookie's Domain attribute is ${cookie.domain}.`,
          basis: "direct",
          establishes: "Every subdomain of that domain receives the cookie.",
          assess: `${whatItCarries} Whether any subdomain is less trusted or can be taken over.`,
          evidence: cookie.domain,
        }),
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

export function analyzeForms(forms, { https }) {
  const findings = [];
  for (const form of forms) {
    const label = form.id ?? form.name ?? `form[${form.index}]`;
    const fields = form.fields ?? [];
    const names = fields
      .map((field) => field.name)
      .filter(Boolean)
      .join(", ");
    const hasPassword = fields.some((field) => field.type === "password");
    const actionHttps = form.action?.startsWith("https://") === true;

    if (hasPassword && form.method === "GET") {
      findings.push(
        finding({
          id: "password-in-query",
          title: `${label} submits a password with GET`,
          observed: `The form has method GET and a password field, submitting to ${form.action}.`,
          basis: "direct",
          establishes:
            "The password is placed in the URL, so it reaches server logs, browser history, and referrers.",
          assess:
            "Whether the form is reachable and functional, rather than dead markup.",
          evidence: form.action,
        }),
      );
    }
    if (hasPassword && !actionHttps && form.action !== null) {
      findings.push(
        finding({
          id: "credentials-over-http",
          title: `${label} posts credentials to a non-HTTPS action`,
          observed: `The form has a password field and submits to ${form.action}.`,
          basis: "direct",
          establishes:
            "The credential travels in cleartext and is readable and alterable in transit.",
          assess:
            "Whether this is the deployment users reach. A development server on loopback is not the same as a production login.",
          evidence: form.action,
        }),
      );
    }
    if (https && form.action !== null && !actionHttps) {
      findings.push(
        finding({
          id: "mixed-form-action",
          title: `${label} on an HTTPS page submits to ${form.action}`,
          observed: `The page is HTTPS and the form action is ${form.action}.`,
          basis: "direct",
          establishes: "The submission leaves the secure origin.",
          assess:
            "What the form submits, and whether a browser would block or warn on it.",
          evidence: form.action,
        }),
      );
    }
    if (
      form.method === "POST" &&
      !fields.some((field) => CSRF_FIELD.test(field.name ?? ""))
    ) {
      findings.push(
        finding({
          id: "csrf-token-absent",
          title: `${label} posts without a token-shaped field`,
          observed: `No field name matches the usual token names. Fields: ${names || "none"}.`,
          basis: "heuristic",
          establishes:
            "Nothing on its own. A token may travel in a header, or the route may rely on SameSite cookies.",
          assess:
            "Resubmit without the token and cross-site, and see whether the route accepts it. That result, not this absence, is the finding.",
          evidence: names,
        }),
      );
    }
    for (const field of fields) {
      if (
        field.type === "password" &&
        field.autocomplete !== "new-password" &&
        field.autocomplete !== "off"
      ) {
        findings.push(
          finding({
            id: "password-autocomplete",
            title: `${label} password field allows autocomplete`,
            observed: `The password field ${field.name ?? "(unnamed)"} sets autocomplete=${field.autocomplete ?? "(unset)"}.`,
            basis: "direct",
            establishes: "A browser may offer to store and refill the value.",
            assess:
              "Whether shared devices are in this application's threat model. Current guidance often prefers password managers, so this may be intended.",
            evidence: field.name ?? "(unnamed)",
          }),
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
          finding({
            id: "secret-in-web-storage",
            title: `${area} holds a key named ${key}`,
            observed: `${area}.${key} is set.`,
            basis: "heuristic",
            establishes:
              "Web storage is readable by any script on the origin, so an injection reads this value.",
            assess:
              "Whether the value is a credential and what it grants. The key name matched a secret-like pattern, which is a guess; read the value.",
            evidence: `${key} = ${String(value).slice(0, 40)}${String(value).length > 40 ? "…" : ""}`,
          }),
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
        finding({
          id: "mixed-content",
          title: `Plaintext subresource from ${parsed.host}`,
          observed: `An HTTPS page loaded ${entry.url} over HTTP.`,
          basis: "direct",
          establishes: "That subresource is readable and alterable in transit.",
          assess:
            "What the resource is. An altered script runs in the page; an altered image does much less.",
          evidence: entry.url,
        }),
      );
    }
    if (pageHost !== undefined && parsed.host !== pageHost)
      thirdParty.add(parsed.host);
    if (
      entry.requestHeaders?.authorization !== undefined &&
      parsed.protocol === "http:"
    ) {
      findings.push(
        finding({
          id: "auth-header-over-http",
          title: `Authorization header sent in cleartext to ${parsed.host}`,
          observed: `${entry.url} was requested over HTTP with an Authorization header.`,
          basis: "direct",
          establishes: "The credential is readable on the wire.",
          assess:
            "What the credential grants, and whether this path runs in production.",
          evidence: entry.url,
        }),
      );
    }
  }
  if (thirdParty.size > 0) {
    findings.push(
      finding({
        id: "third-party-hosts",
        title: `${thirdParty.size} third-party host(s) contacted`,
        observed: `The page requested resources from ${[...thirdParty].join(", ")}.`,
        basis: "direct",
        establishes: "Each host is code or data this page trusts at runtime.",
        assess:
          "Which of them serve script, and whether each is intended. This is inventory, not a weakness by itself.",
        evidence: [...thirdParty].join(", "),
      }),
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
      finding({
        id: "cors-origin-reflected-with-credentials",
        title:
          "The service reflects an arbitrary Origin and allows credentials",
        observed: `Origin: ${sentOrigin} came back as Access-Control-Allow-Origin: ${allowOrigin}, with Access-Control-Allow-Credentials: true.`,
        basis: "direct",
        establishes:
          "A page on any origin can read this response using the visitor's credentials, and the browser will permit the read.",
        assess:
          "What the response body holds for a signed-in caller. Reflection on a response with nothing per-caller is a misconfiguration; on one holding account data it is a cross-origin read of that data.",
        evidence: `Origin: ${sentOrigin} -> Access-Control-Allow-Origin: ${allowOrigin}`,
      }),
    );
  } else if (reflected) {
    findings.push(
      finding({
        id: "cors-origin-reflected",
        title: "The service reflects an arbitrary Origin without credentials",
        observed: `Origin: ${sentOrigin} came back as Access-Control-Allow-Origin: ${allowOrigin}, with no credentials allowed.`,
        basis: "direct",
        establishes:
          "Any origin may read this response, but only as an unauthenticated caller.",
        assess:
          "Whether the response differs from a direct unauthenticated fetch, and whether credentials are allowed on any neighbouring route.",
        evidence: `Origin: ${sentOrigin} -> Access-Control-Allow-Origin: ${allowOrigin}`,
      }),
    );
  }
  if (
    !reflected &&
    allowOrigin !== undefined &&
    allowOrigin !== "*" &&
    !allowOriginVaries
  ) {
    findings.push(
      finding({
        id: "cors-allow-origin-static",
        title: `Access-Control-Allow-Origin is fixed at ${allowOrigin}`,
        observed: `The foreign origin was not echoed; the header stayed ${allowOrigin}.`,
        basis: "direct",
        establishes: "This route does not reflect the request's Origin.",
        assess:
          "Whether the allowed origin is one you control. This is context, not a weakness.",
        evidence: allowOrigin,
      }),
    );
  }
  return findings;
}

/**
 * Directly observed findings first, then the ones resting on a name pattern,
 * so a reader meets the solid facts before the guesses. Deliberately not a
 * severity order: this module does not rate findings.
 */
export function sortFindings(findings) {
  const seen = new Set();
  const order = { direct: 0, heuristic: 1 };
  return findings
    .filter((item) => {
      const key = `${item.id}|${item.evidence ?? ""}|${item.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort(
      (left, right) => (order[left.basis] ?? 2) - (order[right.basis] ?? 2),
    );
}
