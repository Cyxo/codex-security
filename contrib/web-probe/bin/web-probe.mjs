#!/usr/bin/env node
// Drives a Lightpanda CDP server to assess a running web application.
//
// Every action prints one JSON object on stdout, so an agent can parse it
// without scraping prose. Diagnostics go to stderr. Exit 0 means the action
// ran; findings are data, not a failure.

import { writeFile } from "node:fs/promises";
import { openSession, CdpError } from "../src/session.mjs";
import {
  FORM_SNIPPET,
  STORAGE_SNIPPET,
  analyzeCookies,
  analyzeCors,
  analyzeForms,
  analyzeHeaders,
  analyzeStorage,
  analyzeTraffic,
  sortFindings,
} from "../src/analyze.mjs";

const USAGE = `web-probe - assess a running web application through Lightpanda

Usage:
  web-probe <action> <url> [options]

Actions:
  visit       Navigate and report the response, redirects, traffic, and findings
  requests    Navigate and dump every request and response
  headers     Assess the main document's security headers
  cookies     List cookies and assess their flags
  forms       Enumerate forms and assess how they submit
  storage     Dump localStorage and sessionStorage and flag secret-shaped keys
  fill        Fill form fields, optionally submit, and report what was sent
  reflect     Send an inert marker through a parameter and report where it lands
  cors        Send a foreign Origin and report whether the service reflects it
  eval        Evaluate an expression in the page and print its value
  screenshot  Save a PNG of the page
  audit       Run visit, headers, cookies, forms, storage, and merge the findings

Options:
  --cdp URL              CDP endpoint (env WEB_PROBE_CDP, default http://127.0.0.1:9222)
  --header 'N: V'        Extra request header; repeat for more
  --cookie name=value    Cookie to set before navigating; repeat for more
  --field name=value     Form field to fill (fill); repeat for more
  --form SELECTOR        Form to act on (fill), default the first form
  --submit               Submit the form after filling (fill)
  --param NAME           Query parameter to carry the marker (reflect)
  --marker TEXT          Marker to send (reflect), default a generated one
  --origin ORIGIN        Origin to send (cors), default https://cors-probe.invalid
  --expression JS        Expression to evaluate (eval)
  --out PATH             Output file (screenshot)
  --bodies               Include response bodies (requests, visit)
  --max-body BYTES       Truncate each body (default 2048)
  --wait-ms MS           Extra settle time after load (default 500)
  --timeout-ms MS        Per-call timeout (default 20000)
  --cdp-ready-ms MS      How long to wait for the CDP endpoint (default 10000)
  --allow-host HOST      Permit only these target hosts; repeat for more
                         (env WEB_PROBE_ALLOWED_HOSTS, comma separated)
  --pretty               Indent the JSON
  --help

The operator is responsible for having authorization to test the target.
Restrict reachable targets with --allow-host, and run Lightpanda with
--block-private-networks when the target is remote.
`;

const LIST_FLAGS = new Set(["--header", "--cookie", "--field", "--allow-host"]);
const VALUE_FLAGS = new Set([
  "--cdp",
  "--form",
  "--param",
  "--marker",
  "--origin",
  "--expression",
  "--out",
  "--max-body",
  "--wait-ms",
  "--timeout-ms",
  "--cdp-ready-ms",
]);
const BOOLEAN_FLAGS = new Set(["--submit", "--bodies", "--pretty", "--help"]);

function parseArguments(argv) {
  const options = { lists: {} };
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (BOOLEAN_FLAGS.has(argument)) {
      options[argument.slice(2)] = true;
      continue;
    }
    if (LIST_FLAGS.has(argument) || VALUE_FLAGS.has(argument)) {
      const value = argv[(index += 1)];
      if (value === undefined) throw new Error(`${argument} requires a value.`);
      if (LIST_FLAGS.has(argument)) {
        (options.lists[argument.slice(2)] ??= []).push(value);
      } else {
        options[argument.slice(2)] = value;
      }
      continue;
    }
    if (argument.startsWith("-"))
      throw new Error(`Unknown option ${argument}.`);
    positional.push(argument);
  }
  return { options, positional };
}

function parsePairs(values = [], separator = "=") {
  return values.map((entry) => {
    const at = entry.indexOf(separator);
    if (at <= 0)
      throw new Error(`Expected name${separator}value, got ${entry}`);
    return [
      entry.slice(0, at).trim(),
      entry.slice(at + separator.length).trim(),
    ];
  });
}

function requireAllowedHost(url, allowed) {
  const parsed = URL.parse(url);
  if (parsed === null) throw new Error(`Not a valid URL: ${url}`);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(
      `Only http and https targets are supported, got ${parsed.protocol}`,
    );
  }
  if (allowed.length === 0) return parsed;
  if (!allowed.includes(parsed.host) && !allowed.includes(parsed.hostname)) {
    throw new Error(
      `${parsed.host} is not in the allowed target list (${allowed.join(", ")}).`,
    );
  }
  return parsed;
}

function documentOf(requests, url) {
  // The last document response, after redirects, describes the page.
  const documents = requests.filter(
    (entry) =>
      entry.resourceType === "Document" &&
      entry.status !== undefined &&
      entry.redirectedTo === undefined,
  );
  return documents.at(-1) ?? requests.find((entry) => entry.url === url);
}

function redirectChain(requests) {
  return requests
    .filter((entry) => entry.redirectedTo !== undefined)
    .map((entry) => ({
      from: entry.url,
      to: entry.redirectedTo,
      status: entry.status,
    }));
}

async function trafficReport(session, { bodies, maxBody }) {
  const report = [];
  for (const entry of session.requests()) {
    const record = {
      method: entry.method,
      url: entry.url,
      resourceType: entry.resourceType,
      status: entry.status,
      mimeType: entry.mimeType,
      requestHeaders: entry.requestHeaders,
      responseHeaders: entry.responseHeaders,
      ...(entry.postData === undefined
        ? {}
        : { postData: entry.postData.slice(0, maxBody) }),
      ...(entry.redirectedTo === undefined
        ? {}
        : { redirectedTo: entry.redirectedTo }),
      ...(entry.failed === undefined ? {} : { failed: entry.failed }),
      ...(entry.remoteAddress === undefined
        ? {}
        : { remoteAddress: entry.remoteAddress }),
    };
    if (bodies && entry.redirectedTo === undefined) {
      const body = await session.responseBody(entry.requestId);
      if (body !== undefined) {
        record.body = body.slice(0, maxBody);
        record.bodyTruncated = body.length > maxBody;
      }
    }
    report.push(record);
  }
  return report;
}

const ACTIONS = {
  async visit(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const requests = session.requests();
    const document = documentOf(requests, url);
    const finalUrl = await session.evaluate("location.href");
    const title = await session.evaluate("document.title");
    return {
      requestedUrl: url,
      finalUrl,
      title,
      status: document?.status,
      mimeType: document?.mimeType,
      redirects: redirectChain(requests),
      requestCount: requests.length,
      console: session.console,
      traffic: await trafficReport(session, options),
      findings: sortFindings([
        ...analyzeHeaders({
          url: finalUrl ?? url,
          headers: document?.responseHeaders,
          status: document?.status,
        }),
        ...analyzeTraffic(requests, { pageUrl: finalUrl ?? url }),
      ]),
    };
  },

  async requests(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    return {
      url: await session.evaluate("location.href"),
      redirects: redirectChain(session.requests()),
      traffic: await trafficReport(session, {
        ...options,
        bodies: options.bodies ?? true,
      }),
    };
  },

  async headers(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const requests = session.requests();
    const document = documentOf(requests, url);
    const finalUrl = (await session.evaluate("location.href")) ?? url;
    return {
      url: finalUrl,
      status: document?.status,
      responseHeaders: document?.responseHeaders ?? {},
      redirects: redirectChain(requests),
      findings: sortFindings(
        analyzeHeaders({
          url: finalUrl,
          headers: document?.responseHeaders,
          status: document?.status,
        }),
      ),
    };
  },

  async cookies(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const finalUrl = (await session.evaluate("location.href")) ?? url;
    const cookies = await session.cookies();
    return {
      url: finalUrl,
      cookies,
      findings: sortFindings(
        analyzeCookies(cookies, { https: finalUrl.startsWith("https://") }),
      ),
    };
  },

  async forms(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const finalUrl = (await session.evaluate("location.href")) ?? url;
    const forms = (await session.evaluate(FORM_SNIPPET)) ?? [];
    return {
      url: finalUrl,
      forms,
      findings: sortFindings(
        analyzeForms(forms, {
          https: finalUrl.startsWith("https://"),
          pageUrl: finalUrl,
        }),
      ),
    };
  },

  async storage(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const storage = (await session.evaluate(STORAGE_SNIPPET)) ?? {};
    return {
      url: (await session.evaluate("location.href")) ?? url,
      storage,
      findings: sortFindings(analyzeStorage(storage)),
    };
  },

  async fill(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const fields = parsePairs(options.lists.field);
    if (fields.length === 0)
      throw new Error("fill needs at least one --field name=value.");
    const selector = options.form ?? "form";
    const assigned = await session.evaluate(`(() => {
      const form = document.querySelector(${JSON.stringify(selector)});
      if (form === null) return { error: "no form matched the selector" };
      const applied = [];
      const missing = [];
      for (const [name, value] of ${JSON.stringify(fields)}) {
        const field = form.querySelector('[name="' + name + '"]');
        if (field === null) { missing.push(name); continue; }
        field.value = value;
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
        applied.push(name);
      }
      return {
        applied,
        missing,
        action: form.action,
        method: (form.getAttribute("method") || "GET").toUpperCase(),
      };
    })()`);
    if (assigned?.error !== undefined)
      throw new Error(`${assigned.error}: ${selector}`);

    let submission;
    if (options.submit) {
      session.reset();
      await session.evaluate(
        `document.querySelector(${JSON.stringify(selector)}).submit()`,
      );
      // Submitting navigates, so wait for the traffic it causes.
      await new Promise((resolve) =>
        setTimeout(resolve, Number(options.waitMs ?? 500) + 1500),
      );
      submission = {
        finalUrl: await session.evaluate("location.href"),
        title: await session.evaluate("document.title"),
        traffic: await trafficReport(session, {
          ...options,
          bodies: options.bodies ?? true,
        }),
      };
    }
    return {
      url,
      selector,
      ...assigned,
      ...(submission === undefined ? {} : { submission }),
    };
  },

  async reflect(session, url, options) {
    const parameter = options.param;
    if (parameter === undefined) throw new Error("reflect needs --param NAME.");
    const marker =
      options.marker ?? `wpR${Math.random().toString(36).slice(2, 10)}`;
    const target = new URL(url);
    target.searchParams.set(parameter, marker);
    await session.navigate(target.href, { waitMs: options.waitMs });
    const requests = session.requests();
    const document = documentOf(requests, target.href);
    const raw =
      document === undefined
        ? undefined
        : await session.responseBody(document.requestId);
    const inPage = await session.evaluate(`(() => {
      const marker = ${JSON.stringify(marker)};
      const html = document.documentElement.outerHTML;
      const at = html.indexOf(marker);
      const inAttribute = [...document.querySelectorAll("*")].some((node) =>
        [...node.attributes].some((attribute) => attribute.value.includes(marker)),
      );
      return {
        inDom: at !== -1,
        context: at === -1 ? null : html.slice(Math.max(0, at - 90), at + marker.length + 90),
        inAttribute,
        inTitle: document.title.includes(marker),
      };
    })()`);
    return {
      url: target.href,
      parameter,
      marker,
      inResponseBody: raw === undefined ? null : raw.includes(marker),
      ...inPage,
      note:
        inPage?.inDom === true
          ? "The marker reached the DOM unchanged. Read the context for the encoding applied, then decide whether script can be injected there."
          : "The marker did not reach the DOM. Reflection may still occur on another route, parameter, or content type.",
    };
  },

  async cors(session, url, options) {
    // Navigate twice: once plainly, once carrying a foreign Origin, so a
    // reflected value is distinguishable from a fixed one.
    await session.navigate(url, { waitMs: options.waitMs });
    const baseline = documentOf(session.requests(), url)?.responseHeaders ?? {};

    const sentOrigin = options.origin ?? "https://cors-probe.invalid";
    session.reset();
    await session.setExtraHeaders({ Origin: sentOrigin });
    await session.navigate(url, { waitMs: options.waitMs });
    const probed = documentOf(session.requests(), url)?.responseHeaders ?? {};

    const observation = {
      sentOrigin,
      allowOrigin: probed["access-control-allow-origin"],
      allowCredentials: probed["access-control-allow-credentials"],
      allowOriginVaries:
        baseline["access-control-allow-origin"] !==
        probed["access-control-allow-origin"],
    };
    return {
      url,
      withoutOrigin: {
        allowOrigin: baseline["access-control-allow-origin"],
        allowCredentials: baseline["access-control-allow-credentials"],
      },
      ...observation,
      vary: probed.vary,
      findings: sortFindings(analyzeCors(observation)),
    };
  },

  async eval(session, url, options) {
    if (options.expression === undefined)
      throw new Error("eval needs --expression JS.");
    await session.navigate(url, { waitMs: options.waitMs });
    return {
      url: await session.evaluate("location.href"),
      value: await session.evaluate(options.expression),
      console: session.console,
    };
  },

  async screenshot(session, url, options) {
    await session.navigate(url, { waitMs: options.waitMs });
    const shot = await session.call("Page.captureScreenshot", {});
    const path = options.out ?? "screenshot.png";
    await writeFile(path, Buffer.from(shot.data, "base64"));
    return {
      url: await session.evaluate("location.href"),
      path,
      bytes: shot.data.length,
    };
  },

  async audit(session, url, options) {
    const visit = await ACTIONS.visit(session, url, {
      ...options,
      bodies: false,
    });
    const finalUrl = visit.finalUrl ?? url;
    const https = finalUrl.startsWith("https://");
    const cookies = await session.cookies();
    const forms = (await session.evaluate(FORM_SNIPPET)) ?? [];
    const storage = (await session.evaluate(STORAGE_SNIPPET)) ?? {};
    return {
      url: finalUrl,
      status: visit.status,
      title: visit.title,
      redirects: visit.redirects,
      requestCount: visit.requestCount,
      cookies,
      forms,
      storage,
      console: visit.console,
      findings: sortFindings([
        ...visit.findings,
        ...analyzeCookies(cookies, { https }),
        ...analyzeForms(forms, { https, pageUrl: finalUrl }),
        ...analyzeStorage(storage),
      ]),
    };
  },
};

async function main() {
  const { options, positional } = parseArguments(process.argv.slice(2));
  if (options.help || positional.length === 0) {
    process.stdout.write(USAGE);
    return 0;
  }
  const [action, url] = positional;
  const run = Object.hasOwn(ACTIONS, action) ? ACTIONS[action] : undefined;
  if (run === undefined) {
    throw new Error(`Unknown action '${action}'. Run --help for the list.`);
  }
  if (url === undefined) throw new Error(`${action} needs a URL.`);

  const allowed = [
    ...(options.lists["allow-host"] ?? []),
    ...(process.env.WEB_PROBE_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim())
      .filter(Boolean),
  ];
  requireAllowedHost(url, allowed);

  const settings = {
    ...options,
    maxBody: Number(options["max-body"] ?? 2048),
    waitMs: Number(options["wait-ms"] ?? 500),
  };
  const session = await openSession(
    options.cdp ?? process.env.WEB_PROBE_CDP ?? "http://127.0.0.1:9222",
    {
      callTimeoutMs: Number(options["timeout-ms"] ?? 20_000),
      readyTimeoutMs: Number(options["cdp-ready-ms"] ?? 10_000),
    },
  );
  try {
    await session.setExtraHeaders(
      Object.fromEntries(parsePairs(options.lists.header, ":")),
    );
    const cookies = parsePairs(options.lists.cookie).map(([name, value]) => ({
      name,
      value,
      url,
    }));
    await session.setCookies(cookies);
    const result = await run(session, url, settings);
    process.stdout.write(
      `${JSON.stringify({ action, ...result }, null, options.pretty ? 2 : 0)}\n`,
    );
    return 0;
  } finally {
    await session.close();
  }
}

try {
  process.exitCode = await main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`web-probe: ${message}\n`);
  if (error instanceof CdpError) {
    process.stderr.write(
      "web-probe: start the browser with `lightpanda serve --host 127.0.0.1 --port 9222`, or point --cdp at it.\n",
    );
  }
  process.exitCode = 1;
}
