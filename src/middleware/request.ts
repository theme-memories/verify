// Request-shape guards that run before the body is parsed/validated.
// They reject obviously malformed requests cheaply (no Argon2, no Redis).

import type { MiddlewareHandler } from "hono";
import { MAX_BODY_BYTES } from "../config.js";
import { invalidInput } from "../responses.js";

export const requireJsonContentType: MiddlewareHandler = async (c, next) => {
  const contentType = (c.req.header("Content-Type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") return invalidInput(c);
  await next();
};

export const validateContentLength: MiddlewareHandler = async (c, next) => {
  const rawLength = c.req.header("Content-Length");
  if (rawLength !== undefined) {
    if (!/^(0|[1-9]\d*)$/.test(rawLength)) return invalidInput(c);
    const length = Number(rawLength);
    if (!Number.isSafeInteger(length) || length > MAX_BODY_BYTES) {
      return c.json(
        { success: false, errcode: "PAYLOAD_TOO_LARGE" },
        413,
      ) as Response;
    }
  }
  await next();
};
