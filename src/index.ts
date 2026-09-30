import { Hono } from "hono";
import { methodNotAllowed } from "hono/method-not-allowed";
import { secureHeaders } from "hono/secure-headers";
import { loadConfig } from "./config.js";
import { ErrCode } from "./errcode.js";
import type { AppConfig, VerifyResponse } from "./types.js";
import { createVerifyRoute } from "./verify.js";

const welcomeStrings = [
  "Hello Hono!",
  "To learn more about Hono on Vercel, visit https://vercel.com/docs/frameworks/backend/hono",
];

export function createApp(config: AppConfig | undefined): Hono {
  const app = new Hono();

  app.use(
    secureHeaders({
      strictTransportSecurity: false,
      contentSecurityPolicy: { defaultSrc: ["'none'"] },
      xFrameOptions: "DENY",
    }),
  );

  app.use(async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
  });

  app.use(
    methodNotAllowed({
      app,
      onMethodNotAllowed: (c, methods) =>
        c.json<VerifyResponse>(
          { success: false, errcode: ErrCode.METHOD_NOT_ALLOWED },
          405,
          { Allow: methods.join(", ") },
        ),
    }),
  );

  app.get("/", (c) => {
    return c.text(welcomeStrings.join("\n\n"));
  });

  if (config) {
    app.route(config.verifyRoute, createVerifyRoute(config));
  }

  return app;
}

export default createApp(loadConfig(process.env));
