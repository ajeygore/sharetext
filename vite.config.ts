import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The app is served from a sub-path in production (smartlydone.ai/sharetext).
// Dev mirrors that exactly so path handling is never exercised for the first time in prod.
const BASE_PATH = process.env.BASE_PATH || "/sharetext";
const API_TARGET = process.env.API_TARGET || "http://localhost:3000";

export default defineConfig({
  base: `${BASE_PATH}/`,
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      [`${BASE_PATH}/api`]: { target: API_TARGET, changeOrigin: true },
      [`${BASE_PATH}/auth`]: { target: API_TARGET, changeOrigin: true },
    },
  },
});
