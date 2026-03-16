import { Hono } from "hono";
import { MongoClient } from "mongodb";
import argon2 from "argon2";

const app = new Hono();

const welcomeStrings = [
  "Hello Hono!",
  "To learn more about Hono on Vercel, visit https://vercel.com/docs/frameworks/backend/hono",
];

app.get("/", (c) => {
  return c.text(welcomeStrings.join("\n\n"));
});

app.post("/verify", async (c) => {
  const { slug, userinput } = await c.req.json();

  if (!slug || !userinput) {
    return c.json({ success: false, errcode: "MISSING_PARAMS" });
  }

  // IMPORTANT: Replace with your MongoDB connection string
  const client = new MongoClient("mongodb://localhost:27017");

  try {
    await client.connect();
    const db = client.db("mydatabase"); // Replace with your database name
    const collection = db.collection("slugs"); // Replace with your collection name

    const doc = await collection.findOne({ slug });

    if (!doc) {
      return c.json({ success: false, errcode: "NOT_FOUND" });
    }

    const isVerified = await argon2.verify(doc.hashed, userinput);

    if (isVerified) {
      return c.json({ success: true });
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
