// Minimal CDP client for Lightpanda, with no dependencies beyond Node's
// built-in WebSocket (Node 22+).
//
// Only methods Lightpanda 1.1 answers are used. Verified absent in that build:
// `Emulation.enable` and `Page.getResourceTree`. `Fetch.enable` works but
// pauses every request until the client continues it, so this client leaves it
// off; enabling it without a continue handler hangs navigation.

const DEFAULT_CALL_TIMEOUT_MS = 20_000;
const DEFAULT_LOAD_TIMEOUT_MS = 15_000;
const DOMAINS = ["Page", "Network", "Runtime", "DOM", "Log"];

export class CdpError extends Error {}

/** @typedef {{requestId: string, method: string, url: string, resourceType: string|undefined,
 *   requestHeaders: Record<string,string>, postData: string|undefined,
 *   status: number|undefined, statusText: string|undefined, mimeType: string|undefined,
 *   responseHeaders: Record<string,string>, remoteAddress: string|undefined,
 *   fromCache: boolean|undefined, redirectOf: string|undefined,
 *   failed: string|undefined, encodedDataLength: number|undefined}} NetworkEntry */

export async function openSession(endpoint, options = {}) {
  const session = new BrowserSession(endpoint, options);
  await session.open();
  return session;
}

/**
 * Resolve a CDP base URL to its browser WebSocket endpoint, retrying while the
 * endpoint refuses connections. A sidecar browser is often still binding its
 * port when the scanner's first command runs.
 */
export async function resolveWebSocketUrl(
  endpoint,
  { readyTimeoutMs = 10_000 } = {},
) {
  const trimmed = endpoint.replace(/\/+$/, "");
  if (trimmed.startsWith("ws://") || trimmed.startsWith("wss://"))
    return trimmed;
  const deadline = Date.now() + readyTimeoutMs;
  let response;
  let lastError = "no response";
  for (;;) {
    try {
      response = await fetch(`${trimmed}/json/version`, {
        signal: AbortSignal.timeout(5_000),
      });
      break;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      if (Date.now() >= deadline) {
        throw new CdpError(
          `Could not reach ${trimmed}/json/version: ${lastError}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
  }
  if (!response.ok) {
    throw new CdpError(
      `${trimmed}/json/version answered HTTP ${response.status}.`,
    );
  }
  const version = await response.json();
  const url = version.webSocketDebuggerUrl;
  if (typeof url !== "string") {
    throw new CdpError(
      `${trimmed}/json/version returned no webSocketDebuggerUrl.`,
    );
  }
  return url;
}

export class BrowserSession {
  #socket;
  #nextId = 0;
  #pending = new Map();
  #sessionId;
  #targetId;
  #callTimeout;
  #loadTimeout;

  /** @type {Map<string, NetworkEntry>} */
  network = new Map();
  /** @type {{level: string, text: string, url: string|undefined, line: number|undefined}[]} */
  console = [];
  /** @type {string[]} */
  lifecycle = [];

  #readyTimeout;

  constructor(endpoint, { callTimeoutMs, loadTimeoutMs, readyTimeoutMs } = {}) {
    this.endpoint = endpoint;
    this.#callTimeout = callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS;
    this.#loadTimeout = loadTimeoutMs ?? DEFAULT_LOAD_TIMEOUT_MS;
    this.#readyTimeout = readyTimeoutMs;
  }

  async open() {
    const url = await resolveWebSocketUrl(this.endpoint, {
      ...(this.#readyTimeout === undefined
        ? {}
        : { readyTimeoutMs: this.#readyTimeout }),
    });
    this.#socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const onError = () =>
        reject(new CdpError(`Could not open a CDP WebSocket at ${url}.`));
      this.#socket.addEventListener("open", resolve, { once: true });
      this.#socket.addEventListener("error", onError, { once: true });
      setTimeout(() => onError(), this.#callTimeout);
    });
    this.#socket.addEventListener("message", (message) =>
      this.#receive(message),
    );

    const target = await this.call("Target.createTarget", {
      url: "about:blank",
    });
    this.#targetId = target.targetId;
    const attached = await this.call("Target.attachToTarget", {
      targetId: this.#targetId,
      flatten: true,
    });
    this.#sessionId = attached.sessionId;
    for (const domain of DOMAINS) await this.call(`${domain}.enable`);
  }

  #receive(message) {
    let payload;
    try {
      payload = JSON.parse(message.data);
    } catch {
      return;
    }
    if (payload.id !== undefined) {
      const settle = this.#pending.get(payload.id);
      this.#pending.delete(payload.id);
      settle?.(payload);
      return;
    }
    this.#event(payload.method, payload.params ?? {});
  }

  #event(method, params) {
    switch (method) {
      case "Network.requestWillBeSent": {
        // A redirect reuses the request id, so keep the hop before overwriting.
        if (params.redirectResponse !== undefined) {
          const previous = this.network.get(params.requestId);
          if (previous !== undefined) {
            const hop = `${params.requestId}#${this.network.size}`;
            this.network.set(hop, {
              ...previous,
              requestId: hop,
              status: params.redirectResponse.status,
              statusText: params.redirectResponse.statusText,
              mimeType: params.redirectResponse.mimeType,
              responseHeaders: lowercaseKeys(params.redirectResponse.headers),
              redirectedTo: params.request?.url,
            });
          }
        }
        this.network.set(params.requestId, {
          requestId: params.requestId,
          method: params.request?.method,
          url: params.request?.url,
          resourceType: params.type,
          requestHeaders: lowercaseKeys(params.request?.headers),
          postData: params.request?.postData,
          responseHeaders: {},
          redirectOf:
            params.redirectResponse === undefined
              ? undefined
              : params.redirectResponse.url,
        });
        break;
      }
      case "Network.responseReceived": {
        const entry = this.network.get(params.requestId);
        if (entry === undefined) break;
        entry.status = params.response?.status;
        entry.statusText = params.response?.statusText;
        entry.mimeType = params.response?.mimeType;
        entry.responseHeaders = lowercaseKeys(params.response?.headers);
        entry.remoteAddress = params.response?.remoteIPAddress;
        entry.fromCache = params.response?.fromDiskCache;
        break;
      }
      case "Network.loadingFinished": {
        const entry = this.network.get(params.requestId);
        if (entry !== undefined)
          entry.encodedDataLength = params.encodedDataLength;
        break;
      }
      case "Network.loadingFailed": {
        const entry = this.network.get(params.requestId);
        if (entry !== undefined) entry.failed = params.errorText ?? "failed";
        break;
      }
      case "Runtime.consoleAPICalled":
        this.console.push({
          level: params.type ?? "log",
          text: (params.args ?? [])
            .map(
              (argument) =>
                argument.value ?? argument.description ?? argument.type,
            )
            .join(" "),
          url: undefined,
          line: undefined,
        });
        break;
      case "Runtime.exceptionThrown":
        this.console.push({
          level: "exception",
          text:
            params.exceptionDetails?.exception?.description ??
            params.exceptionDetails?.text ??
            "exception",
          url: params.exceptionDetails?.url,
          line: params.exceptionDetails?.lineNumber,
        });
        break;
      case "Log.entryAdded":
        this.console.push({
          level: params.entry?.level ?? "log",
          text: params.entry?.text ?? "",
          url: params.entry?.url,
          line: params.entry?.lineNumber,
        });
        break;
      default:
        if (method.startsWith("Page.")) this.lifecycle.push(method);
    }
  }

  /** @returns {Promise<any>} the method result, or throws CdpError. */
  async call(method, params = {}) {
    if (this.#socket.readyState !== 1) {
      throw new CdpError(`The CDP connection closed before ${method}.`);
    }
    const id = (this.#nextId += 1);
    const answer = await new Promise((resolve) => {
      this.#pending.set(id, resolve);
      this.#socket.send(
        JSON.stringify({
          id,
          method,
          params,
          ...(this.#sessionId === undefined
            ? {}
            : { sessionId: this.#sessionId }),
        }),
      );
      setTimeout(() => {
        if (this.#pending.delete(id)) {
          resolve({
            error: { message: `timed out after ${this.#callTimeout}ms` },
          });
        }
      }, this.#callTimeout);
    });
    if (answer.error !== undefined) {
      throw new CdpError(
        `${method}: ${answer.error.message ?? JSON.stringify(answer.error)}`,
      );
    }
    return answer.result ?? {};
  }

  /** Clear the recorded traffic so one action reports only its own requests. */
  reset() {
    this.network.clear();
    this.console.length = 0;
    this.lifecycle.length = 0;
  }

  async navigate(url, { waitMs } = {}) {
    const loaded = this.#waitForLifecycle("Page.loadEventFired");
    const navigation = await this.call("Page.navigate", { url });
    if (navigation.errorText !== undefined) {
      throw new CdpError(
        `Navigation to ${url} failed: ${navigation.errorText}`,
      );
    }
    await loaded;
    // Scripts started by the load event, such as an XHR, finish after it.
    await new Promise((resolve) => setTimeout(resolve, waitMs ?? 500));
    return navigation;
  }

  #waitForLifecycle(event) {
    return new Promise((resolve) => {
      const deadline = Date.now() + this.#loadTimeout;
      const poll = () => {
        if (this.lifecycle.includes(event) || Date.now() > deadline)
          return resolve();
        setTimeout(poll, 50);
      };
      poll();
    });
  }

  async evaluate(expression) {
    const answer = await this.call("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (answer.exceptionDetails !== undefined) {
      throw new CdpError(
        `Evaluation failed: ${answer.exceptionDetails.exception?.description ?? answer.exceptionDetails.text}`,
      );
    }
    return answer.result?.value;
  }

  async responseBody(requestId) {
    try {
      const body = await this.call("Network.getResponseBody", { requestId });
      return body.base64Encoded
        ? Buffer.from(body.body, "base64").toString("utf8")
        : (body.body ?? "");
    } catch {
      // Bodies are unavailable for redirects, failures, and some resource types.
      return undefined;
    }
  }

  async cookies() {
    const answer = await this.call("Network.getAllCookies");
    return answer.cookies ?? [];
  }

  async setExtraHeaders(headers) {
    if (Object.keys(headers).length === 0) return;
    await this.call("Network.setExtraHTTPHeaders", { headers });
  }

  async setCookies(cookies) {
    if (cookies.length === 0) return;
    await this.call("Network.setCookies", { cookies });
  }

  async close() {
    try {
      if (this.#targetId !== undefined) {
        this.#sessionId = undefined;
        await this.call("Target.closeTarget", { targetId: this.#targetId });
      }
    } catch {
      // A closing browser is not an error for the caller.
    }
    this.#socket?.close();
  }

  /** Requests in arrival order, with redirect hops kept. */
  requests() {
    return [...this.network.values()];
  }
}

function lowercaseKeys(headers) {
  if (headers === undefined || headers === null) return {};
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]),
  );
}
