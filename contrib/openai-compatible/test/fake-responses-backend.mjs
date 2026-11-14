// Minimal /v1/responses backend, used to check that the wrapper takes the
// direct path and starts no bridge when an endpoint speaks Responses natively.
import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 8122);

function event(name, payload) {
  return `event: ${name}\ndata: ${JSON.stringify({ type: name, ...payload })}\n\n`;
}

function handle(request, response, body) {
  if (request.url.startsWith("/v1/models")) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        object: "list",
        data: [{ id: "fake-responses-model", object: "model" }],
      }),
    );
    return;
  }
  if (!request.url.startsWith("/v1/responses")) {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(
      JSON.stringify({ error: { message: `Unknown path ${request.url}` } }),
    );
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(body || "{}");
  } catch {
    parsed = {};
  }
  if (parsed.model === undefined || parsed.input === undefined) {
    response.writeHead(400, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        error: {
          message: "'model' and 'input' are required",
          type: "invalid_request_error",
        },
      }),
    );
    return;
  }

  const message = {
    type: "message",
    id: "msg_fake",
    status: "completed",
    role: "assistant",
    content: [
      {
        type: "output_text",
        text: "hello from the fake responses backend",
        annotations: [],
      },
    ],
  };
  const completed = {
    id: "resp_fake",
    object: "response",
    model: parsed.model,
    status: "completed",
    output: [message],
    usage: { input_tokens: 9, output_tokens: 6, total_tokens: 15 },
  };

  if (!parsed.stream) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(completed));
    return;
  }
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  response.write(
    event("response.created", {
      response: { id: "resp_fake", status: "in_progress" },
    }),
  );
  response.write(
    event("response.output_item.added", {
      output_index: 0,
      item: { ...message, content: [] },
    }),
  );
  response.write(
    event("response.output_text.delta", {
      item_id: "msg_fake",
      output_index: 0,
      content_index: 0,
      delta: "hello",
    }),
  );
  response.write(
    event("response.output_item.done", { output_index: 0, item: message }),
  );
  response.write(event("response.completed", { response: completed }));
  response.end();
}

createServer((request, response) => {
  const chunks = [];
  request.on("data", (part) => chunks.push(part));
  request.on("end", () =>
    handle(request, response, Buffer.concat(chunks).toString("utf8")),
  );
}).listen(PORT, "127.0.0.1", () =>
  console.error(`[responses] listening on ${PORT}`),
);
