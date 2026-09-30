import { createHmac, timingSafeEqual } from "node:crypto";
import type { SignatureCheck } from "./types.js";

const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/i;
const TIMESTAMP_PATTERN = /^\d{1,11}$/;

export function computeSignature(
  secret: string,
  timestamp: string,
  body: string,
): string {
  return createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
}

export function isSignatureValid({
  secret,
  timestamp,
  signature,
  body,
  toleranceSeconds,
  now = Date.now(),
}: SignatureCheck): boolean {
  if (
    !TIMESTAMP_PATTERN.test(timestamp) ||
    !SIGNATURE_PATTERN.test(signature)
  ) {
    return false;
  }

  const nowSeconds = Math.floor(now / 1000);

  if (Math.abs(nowSeconds - Number(timestamp)) > toleranceSeconds) {
    return false;
  }

  const expected = Buffer.from(
    computeSignature(secret, timestamp, body),
    "hex",
  );
  const provided = Buffer.from(signature, "hex");

  return (
    expected.length === provided.length && timingSafeEqual(expected, provided)
  );
}
