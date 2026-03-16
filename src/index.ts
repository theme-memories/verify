import { Hono, Context } from "hono";
import { MongoClient } from "mongodb";
import argon2 from "argon2";

// This type is now for documentation purposes on Vercel, as we use process.env
type Env = {
  MONGO_URI: string;
  HMAC_VERIFY: string;
  HMAC_SIGNING: string;
};

const app = new Hono<{ Bindings: Env }>();

app.post("/subsiding6634", async (c: Context<{ Bindings: Env }>) => {
  // --- Start Sanity Check & Debug Block ---
  // On Vercel, environment variables are in process.env, not c.env
  console.log("--- Vercel Environment Debug (using process.env) ---");
  console.log(`HMAC_VERIFY type: ${typeof process.env.HMAC_VERIFY}`);
  console.log(`HMAC_VERIFY empty: ${!process.env.HMAC_VERIFY}`);
  console.log(`HMAC_SIGNING type: ${typeof process.env.HMAC_SIGNING}`);
  console.log(`HMAC_SIGNING empty: ${!process.env.HMAC_SIGNING}`);

  if (!process.env.HMAC_VERIFY || !process.env.HMAC_SIGNING) {
    const errorMessage =
      "FATAL: Server environment variables 'HMAC_VERIFY' or 'HMAC_SIGNING' are not set. Check Vercel environment variable settings and redeploy.";
    console.error(errorMessage);
    return c.text(errorMessage, 500);
  }
  console.log("--- Debug End: Environment variables seem to be present. ---");
  // --- End Sanity Check & Debug Block ---

  // --- HMAC Verification ---
  const signatureHeader = c.req.header("X-Amia-ReqSig");
  if (!signatureHeader) {
    return c.text("Missing signature", 401);
  }

  const body = await c.req.text();

  const encoder = new TextEncoder();
  // Use process.env here
  const verifyKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(process.env.HMAC_VERIFY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    verifyKey,
    encoder.encode(body),
  );
  const computedSignature = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (computedSignature !== signatureHeader) {
    return c.text("Invalid signature", 401);
  }
  // --- End HMAC Verification ---

  const { slug, userinput } = JSON.parse(body);

  // --- Input Validation ---
  const slugRegex = /^[a-zA-Z0-9_-]+$/;
  if (!slug || typeof slug !== "string" || !slugRegex.test(slug)) {
    return c.json({ success: false, errcode: "INVALID_SLUG_FORMAT" }, 400);
  }

  const passwordRegex = /^[a-zA-Z0-9!@#$%^&*]+$/;
  if (
    !userinput ||
    typeof userinput !== "string" ||
    !passwordRegex.test(userinput)
  ) {
    return c.json({ success: false, errcode: "INVALID_PASSWORD_FORMAT" }, 400);
  }
  // --- End Input Validation ---

  if (!process.env.MONGO_URI) {
    console.error("FATAL: MONGO_URI is not set in environment variables.");
    return c.text("Database connection string is not configured.", 500);
  }
  const client = new MongoClient(process.env.MONGO_URI); // Use process.env here

  try {
    await client.connect();
    const db = client.db("theme-memories");
    const collection = db.collection("hash");

    const doc = await collection.findOne({ slug });

    if (!doc) {
      return c.json({ success: false, errcode: "NOT_FOUND" });
    }

    const isVerified = await argon2.verify(doc.hashed, userinput);

    if (isVerified) {
      const responsePayload = { success: true };
      const responseBody = JSON.stringify(responsePayload);

      // Use process.env here
      const signingKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(process.env.HMAC_SIGNING),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );

      const responseSignature = await crypto.subtle.sign(
        "HMAC",
        signingKey,
        encoder.encode(responseBody),
      );
      const responseSignatureHex = Array.from(new Uint8Array(responseSignature))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      c.header("X-Amia-ResSig", responseSignatureHex);
      return c.json(responsePayload);
    } else {
      return c.json({ success: false, errcode: "INVALID_INPUT" });
    }
  } catch (err) {
    console.error(err);
    return c.json({ success: false, errcode: "INTERNAL_ERROR" });
  } finally {
    await client.close();
  }
});

export default app;
