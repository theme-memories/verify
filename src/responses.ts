// Common JSON response envelopes shared by middlewares and the verify handler.
// Keeping them here ensures consistent `success`/`errcode` shapes everywhere.

import type { Context } from "hono";

export function invalidInput(c: Context): Response {
  return c.json({ success: false, errcode: "INVALID_INPUT" }, 400) as Response;
}

export function verifyFailed(c: Context) {
  return c.json({ success: false, errcode: "VERIFY_FAILED" }, 200);
}
