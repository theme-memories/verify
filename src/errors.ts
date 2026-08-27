export function errorCodeForStatus(status: number): string {
  switch (status) {
    case 400:
      return "INVALID_REQUEST";
    case 401:
      return "UNAUTHORIZED";
    case 403:
      return "FORBIDDEN";
    case 404:
      return "NOT_FOUND";
    case 408:
      return "REQUEST_CANCELLED";
    case 413:
      return "PAYLOAD_TOO_LARGE";
    case 429:
      return "TOO_MANY_REQUESTS";
    case 504:
      return "TIMEOUT";
    default:
      return "REQUEST_FAILED";
  }
}
