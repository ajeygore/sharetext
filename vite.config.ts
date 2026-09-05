import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Empty means the app owns the domain root (share.tnkrhaus.dev). Set BASE_PATH
// only to mount it under a path on a shared domain. This is baked into the
// bundle at build time, so it must match the server's BASE_PATH.
const BASE_PATH = (process.env.BASE_PATH ?? "").replace(/\/$/, "");
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
