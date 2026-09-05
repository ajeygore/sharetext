import { buildApp } from "./app";
import { BASE_PATH, GOOGLE_CONFIGURED, PORT, PUBLIC_ORIGIN } from "./config";

const app = buildApp();

console.log(`ShareText listening on :${PORT}  ->  ${PUBLIC_ORIGIN}${BASE_PATH}/`);
if (!GOOGLE_CONFIGURED) {
  console.warn("Google OAuth is not configured — sign-in will be unavailable.");
}

export default { port: PORT, fetch: app.fetch };
