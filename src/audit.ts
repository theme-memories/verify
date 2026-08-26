// Structured audit logging. Every verification attempt (success or failure)
// is emitted as a single JSON line on stdout so it can be ingested by the
// platform's log pipeline. The token subject (`sub`) is included for tracing.

import type { Context } from "hono";

export function auditVerify(
  c: Context,
  success: boolean,
  errcode: string | null,
) {
  const sub =
    (c.get("jwtPayload") as { sub?: string } | undefined)?.sub ?? "unknown";
  console.info(JSON.stringify({ event: "verify", sub, success, errcode }));
}
