import type { ErrCodeValue } from "./errcode.js";

export type AppConfig = {
  verifyRoute: string;
  hmacSecret: string;
  argon2Pepper?: string;
};

export type VerifyResponse = {
  success: boolean;
  errcode: ErrCodeValue;
};

export type VerifyPayload = {
  desired_hash: string;
  user_input: string;
};

export type SignatureCheck = {
  secret: string;
  timestamp: string;
  signature: string;
  body: string;
  toleranceSeconds: number;
  now?: number;
};
