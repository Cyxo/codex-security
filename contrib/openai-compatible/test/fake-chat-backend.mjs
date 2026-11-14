// OpenAI-compatible /v1/chat/completions backend used to validate a bridge.
// Logs every request to chat-requests.ndjson and replies with a scripted
// tool call followed by text, in streaming or non-streaming form.
import { createServer } from "node:http";
import { appendFileSync } from "node:fs";

const LOG = new URL("./chat-requests.ndjson", import.meta.url).pathname;
const PORT = Number(process.env.PORT ?? 8111);
const MODEL = "fake-chat-model";

const TOOL_CALL = {
  id: "call_fake_1",
  type: "function",
  function: {
    name: process.env.FAKE_TOOL ?? "exec_command",
    arguments: process.env.FAKE_TOOL_ARGS ?? JSON.stringify({ cmd: "ls" }),
  },
};

function chunk(delta, finish = null) {
  return `data: ${JSON.stringify({
    id: "chatcmpl-fake",
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: MODEL,
    choices: [{ index: 0, delta, finish_reason: finish }],
  })}\n\n`;
}

function handle(request, response, body) {
  appendFileSync(
    LOG,
    JSON.stringify({ url: request.url, headers: request.headers, body }) + "\n",
  );
  let parsed;
  try {
    parsed = JSON.parse(body || "{}");
  } catch {
    parsed = {};
  }
  console.error(
    `[chat] ${request.method} ${request.url} stream=${!!parsed.stream} tools=${parsed.tools?.length ?? 0}`,
  );

  if (request.url.startsWith("/v1/models")) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        object: "list",
        data: [{ id: MODEL, object: "model" }],
      }),
    );
    return;
  }

  // Anything other than chat completions is absent, like a real chat-only server.
  if (!request.url.startsWith("/v1/chat/completions")) {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        error: { message: `Unknown path ${request.url}`, type: "not_found" },
      }),
    );
    return;
  }

  // STRICT=1 mimics a server that rejects unknown top-level fields.
  const KNOWN = new Set([
    "model",
    "messages",
    "tools",
    "tool_choice",
    "stream",
    "stream_options",
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "stop",
    "n",
    "parallel_tool_calls",
    "seed",
    "user",
    "response_format",
    "logprobs",
    "frequency_penalty",
    "presence_penalty",
  ]);
  if (process.env.STRICT === "1") {
    const unknown = Object.keys(parsed).filter((key) => !KNOWN.has(key));
    if (unknown.length > 0) {
      response.writeHead(400, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          error: {
            message: `Unrecognized request arguments: ${unknown.join(", ")}`,
            type: "invalid_request_error",
          },
        }),
      );
      return;
    }
  }

  if (parsed.model === undefined || parsed.messages === undefined) {
    response.writeHead(400, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        error: {
          message: "'model' and 'messages' are required",
          type: "invalid_request_error",
        },
      }),
    );
    return;
  }

  // Reply with a tool call only when the caller offered tools and has not yet
  // produced one, so a bridge round-trip exercises both directions.
  const alreadyCalled = (parsed.messages ?? []).some(
    (message) => message.role === "tool" || message.tool_calls?.length,
  );
  const wantsTool = (parsed.tools?.length ?? 0) > 0 && !alreadyCalled;

  if (!parsed.stream) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        id: "chatcmpl-fake",
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: MODEL,
        choices: [
          {
            index: 0,
            message: wantsTool
              ? { role: "assistant", content: null, tool_calls: [TOOL_CALL] }
              : { role: "assistant", content: "hello from the fake backend" },
            finish_reason: wantsTool ? "tool_calls" : "stop",
          },
        ],
        usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
      }),
    );
    return;
  }

  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  response.write(chunk({ role: "assistant" }));
  if (wantsTool) {
    response.write(chunk({ tool_calls: [{ index: 0, ...TOOL_CALL }] }));
    response.write(chunk({}, "tool_calls"));
  } else {
    response.write(chunk({ content: "hello " }));
    response.write(chunk({ content: "from the fake backend" }));
    response.write(chunk({}, "stop"));
  }
  response.write(
    `data: ${JSON.stringify({
      id: "chatcmpl-fake",
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: MODEL,
      choices: [],
      usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
    })}\n\n`,
  );
  response.write("data: [DONE]\n\n");
  response.end();
}

createServer((request, response) => {
  const chunks = [];
  request.on("data", (part) => chunks.push(part));
  request.on("end", () =>
    handle(request, response, Buffer.concat(chunks).toString("utf8")),
  );
}).listen(PORT, "127.0.0.1", () =>
  console.error(`[chat] listening on ${PORT}`),
);
