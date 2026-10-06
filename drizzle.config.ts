import { defineConfig } from "drizzle-kit";
import fs from "node:fs";

// Read .env.local manually so drizzle-kit works without extra tooling.
// Drizzle-kit runs outside Next.js, so it never sees the framework's env loader.
const envLocal = Object.fromEntries(
  fs
    .readFileSync(".env.local", "utf8")
    .split("\n")
    .filter((l) => l.includes("=") && !l.startsWith("#"))
    .map((l) => {
      const i = l.indexOf("=");
      return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    }),
);

export default defineConfig({
  schema: "./src/lib/db/schema.ts",
  out: "./drizzle",
  dialect: "turso",
  dbCredentials: {
    url: envLocal.TURSO_DATABASE_URL,
    authToken: envLocal.TURSO_AUTH_TOKEN,
  },
  verbose: true,
  strict: true,
});