export const ErrCode = {
  OK: 0,
  METHOD_NOT_ALLOWED: 1,
  INVALID_REQUEST: 2,
  UNAUTHORIZED: 3,
  INVALID_HASH: 4,
  INTERNAL_ERROR: 5,
  MISMATCH: 6,
} as const;

export type ErrCodeValue = (typeof ErrCode)[keyof typeof ErrCode];
