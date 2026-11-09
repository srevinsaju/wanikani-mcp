import { defineConfig } from "vite";

// `bun run preview`: every view with sample data, outside a host, for
// working on the views. Never built or shipped.
export default defineConfig({
  root: "preview",
  server: { port: 5183, fs: { allow: [".."] } },
});
