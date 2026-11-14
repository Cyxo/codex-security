// Endpoint capability detection for OpenAI-compatible servers.
//
// Codex 0.167 speaks only the Responses wire protocol, so the wrapper needs to
// know whether a base URL serves `/responses` natively or only
// `/chat/completions`. Probing with an empty JSON body costs no tokens: a
// server that implements the route rejects it with a validation error, while a
// server that does not returns 404 or 405.

/** @typedef {"responses" | "chat" | "both" | "none"} EndpointKind */

/**
 * @typedef {object} ProbeResult
 * @property {string} path
 * @property {boolean} implemented
 * @property {number | null} status
 * @property {string} detail
 */

/**
 * @typedef {object} DetectionResult
 * @property {EndpointKind} kind
 * @property {string} baseUrl
 * @property {ProbeResult} responses
 * @property {ProbeResult} chat
 * @property {string[]} models
 */

const PROBE_TIMEOUT_MS = 10_000;

export function normalizeBaseUrl(baseUrl) {
  const trimmed = String(baseUrl ?? "")
    .trim()
    .replace(/\/+$/, "");
  if (trimmed === "") throw new Error("A base URL is required.");
  const parsed = URL.parse(trimmed);
  if (parsed === null) throw new Error(`Not a valid base URL: ${baseUrl}`);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Base URL must be http or https: ${baseUrl}`);
  }
  return trimmed;
}

async function request(url, { apiKey, method = "POST", body, signal }) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  const response = await fetch(url, { method, headers, body, signal });
  return {
    status: response.status,
    text: (await response.text()).slice(0, 2000),
  };
}

/** An empty body separates "route missing" from "route present but unhappy". */
async function probe(baseUrl, path, apiKey) {
  const url = `${baseUrl}/${path}`;
  let status = null;
  let text = "";
  try {
    ({ status, text } = await request(url, {
      apiKey,
      body: "{}",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    }));
  } catch (error) {
    return {
      path,
      implemented: false,
      status: null,
      detail: `unreachable: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (status === 404 || status === 405 || status === 501) {
    return { path, implemented: false, status, detail: "route not served" };
  }
  if (status === 401 || status === 403) {
    return { path, implemented: false, status, detail: "rejected the API key" };
  }
  // 400/422 is the expected answer to an empty body; 200 means a lenient server.
  return {
    path,
    implemented: status < 500,
    status,
    detail:
      status < 500 ? "route served" : `server error: ${text.slice(0, 200)}`,
  };
}

async function listModels(baseUrl, apiKey) {
  try {
    const { status, text } = await request(`${baseUrl}/models`, {
      apiKey,
      method: "GET",
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (status !== 200) return [];
    const parsed = JSON.parse(text);
    const data = Array.isArray(parsed?.data) ? parsed.data : [];
    return data
      .map((entry) => entry?.id)
      .filter((id) => typeof id === "string");
  } catch {
    return [];
  }
}

/**
 * @param {string} baseUrl Base URL including any `/v1` suffix.
 * @param {string} [apiKey]
 * @returns {Promise<DetectionResult>}
 */
export async function detectEndpoint(baseUrl, apiKey) {
  const normalized = normalizeBaseUrl(baseUrl);
  const [responses, chat, models] = await Promise.all([
    probe(normalized, "responses", apiKey),
    probe(normalized, "chat/completions", apiKey),
    listModels(normalized, apiKey),
  ]);
  const kind =
    responses.implemented && chat.implemented
      ? "both"
      : responses.implemented
        ? "responses"
        : chat.implemented
          ? "chat"
          : "none";
  return { kind, baseUrl: normalized, responses, chat, models };
}

/** Codex can talk to the endpoint directly when it serves `/responses`. */
export function needsBridge(detection) {
  return detection.kind === "chat";
}

export function describeDetection(detection) {
  const line = (probeResult) =>
    `${probeResult.path}: ${probeResult.implemented ? "yes" : "no"}` +
    ` (${probeResult.status ?? "no response"}, ${probeResult.detail})`;
  return [
    `base URL      ${detection.baseUrl}`,
    `  ${line(detection.responses)}`,
    `  ${line(detection.chat)}`,
    `  models: ${detection.models.length > 0 ? detection.models.slice(0, 8).join(", ") : "not listed"}`,
  ].join("\n");
}
