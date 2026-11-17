// The recipes for stacks the Express middleware does not mount on (skills/agent-traffic/recipes). Each must send the
// event the middleware would: the same name for the same route, the same redacted path, the same account and IP
// hashes. Otherwise one product's reports name the same route differently depending on the customer's framework.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { eventName, hashIp, redactPath } = require("../skills/agent-traffic/agent-traffic.cjs");
const RECIPES = fileURLToPath(new URL("../skills/agent-traffic/recipes/", import.meta.url));
const python = spawnSync("python3", ["--version"]).status === 0;

// Runs Python with the recipe importable as "fastapi_recipe" and returns what it prints as JSON.
function py(code, input) {
  const program = `import importlib.util, json, sys\nspec = importlib.util.spec_from_file_location("fastapi_recipe", ${JSON.stringify(`${RECIPES}fastapi.py`)})\nr = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(r)\ndata = json.loads(sys.stdin.read())\n${code}`;
  return JSON.parse(execFileSync("python3", ["-c", program], { input: JSON.stringify(input), encoding: "utf8" }));
}

describe("FastAPI recipe matches the Express middleware", { skip: !python && "python3 is not installed" }, () => {
  test("event names: the same rule for any route pattern and method", () => {
    const cases = [
      ["/notes", "GET"], ["/notes", "POST"], ["/notes", "HEAD"], ["/v1/notes/{note_id}", "GET"], ["/api/v2/api-keys", "POST"],
      ["/", "GET"], ["/v1", "GET"], ["/api", "DELETE"], ["/Users/{userId}/Orders/{order_id}", "PATCH"], ["/123/abc", "GET"],
      ["/health-check", "GET"], ["/a/very/long/route/pattern/that/goes/on/and/on/with/many/segments/until/it/passes/sixty/four", "PUT"],
      ["/files/{path:path}", "GET"], ["/v10/items/", "GET"],
    ];
    const names = py("print(json.dumps([r.event_name(p, m) for p, m in data]))", cases);
    assert.deepEqual(names, cases.map(([path, method]) => eventName({ route: { path }, method })));
    assert.deepEqual(py("print(json.dumps(r.event_name(None, 'GET')))", null), "unmatched");
    assert.equal(names[3], "notes_note_id");
  });

  test("paths: secret-looking segments become :token, ids and route names stay", () => {
    const paths = [
      "/v1/users/123", "/invite/3f2a9c1e7b4d5a6f", "/reset/550e8400-e29b-41d4-a716-446655440000", "/orders/550e8400-e29b-41d4-a716-446655440000",
      "/files/0123456789abcdef0123456789abcdef", "/files/0123456789abcdef01234567", "/t/eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4",
      "/keys/sk_live_Ab12Cd34Ef56Gh78Ij90", "/docs/reset-password-confirmation", "/oauth2-callback/done", "/verify/AbCdEf0123456789", "/verify/short",
      "/a/b3BlbnNlc2FtZTEyMzQ1Njc4OTA%3D", "/customers/cus_123", "/",
    ];
    assert.deepEqual(py("print(json.dumps([r.redact_path(p) for p in data]))", paths), paths.map(redactPath));
  });

  test("ip_hash and account_id: the same bytes", () => {
    const at = "2026-11-17T20:00:00.000Z";
    const ips = ["203.0.113.7", "::ffff:203.0.113.7", "2001:db8:85a3:8d3:1319:8a2e:370:7348", "2001:DB8::1", "fe80::1%en0", "::1", " 198.51.100.4 ", "not-an-ip", ""];
    assert.deepEqual(py("print(json.dumps([r.hash_ip(ip, 'salt', data['at']) for ip in data['ips']]))", { at, ips }), ips.map((ip) => hashIp(ip, "salt", at) ?? null));
    assert.equal(py("print(json.dumps(r.hash_account_id('user_alice', 'salt')))", null), createHmac("sha256", "salt").update("user_alice").digest("hex"));
  });

  test("the middleware sends one event per request with the status the app answered, and 500 when it raised", () => {
    const events = py(`
import asyncio, os
os.environ["AGENT_TRAFFIC_KEY"] = "ark_ws_fake"
os.environ["AGENT_TRAFFIC_ACCOUNT_SALT"] = "salt"
class Route:
    def __init__(self, path): self.path = path
async def app(scope, receive, send):
    if scope["path"] == "/boom":
        raise RuntimeError("boom")
    if scope["path"].startswith("/notes/"):
        scope["route"] = Route("/notes/{note_id}")
        scope.setdefault("state", {})["account_id"] = "user_alice"
    await send({"type": "http.response.start", "status": 404 if scope["path"] == "/nope" else 200, "headers": []})
    await send({"type": "http.response.body", "body": b""})
sent = []
mw = r.TrackMiddleware(app, account_id_of=lambda scope: scope.get("state", {}).get("account_id"))
mw.post = lambda batch: sent.extend(batch)
async def call(path, method="GET"):
    scope = {"type": "http", "method": method, "path": path, "headers": [(b"User-Agent", b"Claude-User (claude-code/2.1)")], "client": ("203.0.113.7", 5000)}
    async def receive(): return {"type": "http.request"}
    async def send(message): pass
    try:
        await mw(scope, receive, send)
    except RuntimeError:
        pass
async def main():
    await call("/notes/n1")
    await call("/nope")
    await call("/boom")
    await mw({"type": "lifespan"}, None, None) if False else None
asyncio.run(main())
mw.flush()
print(json.dumps(sent))`, null);
    assert.deepEqual(events.map((e) => [e.name, e.path, e.properties.status_code, e.properties.method, e.source, e.user_agent]), [
      ["notes_note_id", "/notes/n1", 200, "GET", "sdk", "Claude-User (claude-code/2.1)"],
      ["unmatched", "/nope", 404, "GET", "sdk", "Claude-User (claude-code/2.1)"],
      ["unmatched", "/boom", 500, "GET", "sdk", "Claude-User (claude-code/2.1)"],
    ]);
    assert.equal(events[0].account_id, createHmac("sha256", "salt").update("user_alice").digest("hex"));
    assert.equal(events[1].account_id, undefined);
    assert.equal(events[0].ip_hash, hashIp("203.0.113.7", "salt", events[0].occurred_at));
    assert.match(events[0].occurred_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.match(events[0].idempotency_key, /^[0-9a-f-]{36}$/);
  });
});

describe("Fastify recipe hands requests to the Express middleware", () => {
  // A stand-in for Fastify over a real HTTP server: addHook collects the hooks, each request runs onRequest, then
  // "auth" sets request.user, then the route answers. Enough to exercise the adapter without depending on fastify.
  async function withApp(run) {
    const sent = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      if (!String(url).startsWith("https://ingest.test")) return realFetch(url, init);
      const batch = JSON.parse(init.body);
      sent.push(...batch);
      return new Response(JSON.stringify({ accepted: batch.length, rejected: [] }), { status: 202, headers: { "content-type": "application/json" } });
    };
    const hooks = [];
    const fastify = { addHook: (name, hook) => { assert.equal(name, "onRequest"); hooks.push(hook); } };
    const { trackFastify } = require("../skills/agent-traffic/recipes/fastify.cjs");
    trackFastify(fastify, { key: "ark_ws_fake", salt: "salt", endpoint: "https://ingest.test", accountIdOf: (request) => request.user?.id });
    const routes = { "/health": "/health", "/v1/notes/42": "/v1/notes/:id" };
    const server = createServer((raw, res) => {
      const path = raw.url.split("?")[0];
      const request = { method: raw.method, headers: raw.headers, raw, protocol: "http", ip: "203.0.113.7", is404: !(path in routes), routeOptions: { url: routes[path] } };
      hooks[0](request, { raw: res }, () => {
        if (raw.headers.authorization) request.user = { id: "user_alice" };
        res.statusCode = request.is404 ? 404 : raw.headers["x-fail"] ? 401 : 200;
        res.end("{}");
      });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      await run(`http://127.0.0.1:${server.address().port}`, sent, realFetch);
    } finally {
      globalThis.fetch = realFetch;
      await new Promise((resolve) => server.close(resolve));
    }
  }
  const flushed = () => new Promise((resolve) => setTimeout(resolve, 1300));

  test("one event per request, named by the route pattern, with the account auth set after onRequest", async () => {
    await withApp(async (base, sent, fetch) => {
      await fetch(`${base}/health`);
      await fetch(`${base}/v1/notes/42?token=secret`, { headers: { authorization: "Bearer t", "user-agent": "Claude-User (claude-code/2.1)" } });
      await fetch(`${base}/v1/notes/42`, { headers: { "x-fail": "1" } });
      await fetch(`${base}/nope`);
      await flushed();
      assert.deepEqual(sent.map((e) => [e.name, e.path, e.properties.status_code]), [["health", "/health", 200], ["notes_id", "/v1/notes/42", 200], ["notes_id", "/v1/notes/42", 401], ["unmatched", "/nope", 404]]);
      assert.equal(sent[1].account_id, createHmac("sha256", "salt").update("user_alice").digest("hex"));
      assert.equal(sent[0].account_id, undefined);
      assert.equal(sent[1].user_agent, "Claude-User (claude-code/2.1)");
      assert.equal(sent[1].ip_hash, hashIp("203.0.113.7", "salt", sent[1].occurred_at));
      assert.doesNotMatch(JSON.stringify(sent), /secret|user_alice/);
    });
  });

  test("a response that emits finish twice (fastify.inject does) still sends one event", async () => {
    const sent = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const batch = JSON.parse(init.body);
      sent.push(...batch);
      return new Response(JSON.stringify({ accepted: batch.length, rejected: [] }), { status: 202, headers: { "content-type": "application/json" } });
    };
    try {
      let hook;
      const { trackFastify } = require("../skills/agent-traffic/recipes/fastify.cjs");
      trackFastify({ addHook: (name, fn) => { hook = fn; } }, { key: "ark_ws_fake", salt: "salt", endpoint: "https://ingest.test" });
      const raw = Object.assign(new EventEmitter(), { statusCode: 200, getHeader: () => undefined, setHeader: () => {} });
      const request = { method: "GET", headers: {}, raw: { url: "/health", socket: {} }, protocol: "http", ip: "203.0.113.7", is404: false, routeOptions: { url: "/health" } };
      hook(request, { raw }, () => {});
      raw.emit("finish");
      raw.emit("finish");
      await flushed();
      assert.deepEqual(sent.map((e) => e.name), ["health"]);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
