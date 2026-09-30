import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { needsRehash, verify } from "argon2";
import {
  ARGON2ID_PREFIX,
  ARGON2_VERIFY_OPTIONS,
  CONTENT_TYPE,
  HMAC_TIMESTAMP_TOLERANCE_SECONDS,
  MAX_BODY_BYTES,
  MAX_HASH_LENGTH,
  MAX_USER_INPUT_LENGTH,
  MIN_USER_INPUT_LENGTH,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
  USER_INPUT_PATTERN,
} from "./config.js";
import { ErrCode, type ErrCodeValue } from "./errcode.js";
import { isSignatureValid } from "./hmac.js";
import {
  type AppConfig,
  type VerifyPayload,
  type VerifyResponse,
} from "./types.js";

function verifyError(
  c: Context,
  errcode: ErrCodeValue,
  status: ContentfulStatusCode,
) {
  return c.json<VerifyResponse>({ success: false, errcode }, status);
}

function isVerifyPayload(body: unknown): body is VerifyPayload {
  if (typeof body !== "object" || body === null) {
    return false;
  }

  const { desired_hash: desiredHash, user_input: userInput } = body as Record<
    string,
    unknown
  >;

  return (
    typeof desiredHash === "string" &&
    desiredHash.length > 0 &&
    desiredHash.length <= MAX_HASH_LENGTH &&
    typeof userInput === "string" &&
    userInput.length >= MIN_USER_INPUT_LENGTH &&
    userInput.length <= MAX_USER_INPUT_LENGTH &&
    USER_INPUT_PATTERN.test(userInput)
  );
}

export function createVerifyRoute(config: AppConfig): Hono {
  const route = new Hono();
  // The pepper is the literal env string's UTF-8 bytes, not its base64 decode;
  // the hashing side must feed Argon2 the same bytes.
  const verifyOptions =
    config.argon2Pepper === undefined
      ? undefined
      : { secret: Buffer.from(config.argon2Pepper, "utf8") };

  route.post(
    "/",
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (c) => verifyError(c, ErrCode.INVALID_REQUEST, 413),
    }),
    async (c) => {
      const timestamp = c.req.header(TIMESTAMP_HEADER) ?? "";
      const signature = c.req.header(SIGNATURE_HEADER) ?? "";

      let rawBody: string;

      try {
        rawBody = await c.req.text();
      } catch {
        return verifyError(c, ErrCode.INVALID_REQUEST, 400);
      }

      const authorized = isSignatureValid({
        secret: config.hmacSecret,
        timestamp,
        signature,
        body: rawBody,
        toleranceSeconds: HMAC_TIMESTAMP_TOLERANCE_SECONDS,
      });

      if (!authorized) {
        return verifyError(c, ErrCode.UNAUTHORIZED, 401);
      }

      const contentType = (c.req.header("content-type") ?? "")
        .trim()
        .toLowerCase();

      if (contentType !== CONTENT_TYPE) {
        return verifyError(c, ErrCode.INVALID_REQUEST, 415);
      }

      let body: unknown;

      try {
        body = JSON.parse(rawBody);
      } catch {
        return verifyError(c, ErrCode.INVALID_REQUEST, 400);
      }

      if (!isVerifyPayload(body)) {
        return verifyError(c, ErrCode.INVALID_REQUEST, 400);
      }

      try {
        if (
          !body.desired_hash.startsWith(ARGON2ID_PREFIX) ||
          needsRehash(body.desired_hash, ARGON2_VERIFY_OPTIONS)
        ) {
          return verifyError(c, ErrCode.INVALID_HASH, 400);
        }
      } catch {
        return verifyError(c, ErrCode.INVALID_HASH, 400);
      }

      let matches: boolean;

      try {
        matches = await verify(
          body.desired_hash,
          body.user_input,
          verifyOptions,
        );
      } catch {
        return verifyError(c, ErrCode.INTERNAL_ERROR, 500);
      }

      if (!matches) {
        return verifyError(c, ErrCode.MISMATCH, 200);
      }

      return c.json<VerifyResponse>(
        { success: true, errcode: ErrCode.OK },
        200,
      );
    },
  );

  return route;
}
