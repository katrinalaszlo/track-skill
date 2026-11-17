// Track on Fastify. Copy this file into your app as track-fastify.cjs (.cjs so it loads the same way whether your
// package.json says "type": "module" or not).
//
// @katrinalaszlo/track is Express middleware and does not mount on Fastify (fastify.use is not a function). This
// hands the middleware each Fastify request and reply in the shape it reads, so everything else is the package's own
// code: event names, path redaction, account and IP hashing, batching, retries and reading .env.
//
//   const { trackFastify } = require("./track-fastify.cjs");      // or: import { trackFastify } from "./track-fastify.cjs";
//   trackFastify(fastify, { accountIdOf: (request) => request.user?.id });
//
// Call it before your routes are registered. accountIdOf gets the Fastify request after your auth hooks ran and
// returns the customer id they resolved, or undefined. The other options are agentTraffic's (errorOf and pathOf get
// the same object as req.fastify).
const { agentTraffic } = require("@katrinalaszlo/track");

function trackFastify(fastify, { accountIdOf, ...options } = {}) {
  const middleware = agentTraffic({ ...options, accountIdOf: accountIdOf ? (req) => accountIdOf(req.fastify) : undefined });
  fastify.addHook("onRequest", (request, reply, done) => {
    const raw = reply.raw;
    const req = {
      fastify: request,
      method: request.method,
      headers: request.headers,
      url: request.raw.url,
      originalUrl: request.raw.url,
      protocol: request.protocol,
      ip: request.ip,
      socket: request.raw.socket,
      // Read when the response finishes. A request no route matched has no pattern and is named "unmatched".
      get route() {
        return request.is404 ? undefined : { path: request.routeOptions.url };
      },
    };
    const res = {
      locals: {},
      get statusCode() {
        return raw.statusCode;
      },
      getHeader: (name) => raw.getHeader(name),
      setHeader: (name, value) => raw.setHeader(name, value),
      // once, not on: fastify.inject (tests) emits finish twice, which would send every event twice.
      on: (event, listener) => (event === "finish" ? raw.once(event, listener) : raw.on(event, listener)),
    };
    middleware(req, res, done);
  });
}

module.exports = { trackFastify };
