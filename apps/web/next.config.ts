import path from "node:path";
import type { NextConfig } from "next";

const API = process.env.PAYLINEAGE_API_URL ?? "http://localhost:8000";

const ROOT = path.join(import.meta.dirname, "../..");

const config: NextConfig = {
  reactStrictMode: true,
  // The container image runs the self contained server (apps/web/Dockerfile).
  ...(process.env.NEXT_OUTPUT === "standalone" ? { output: "standalone", outputFileTracingRoot: ROOT } : {}),
  poweredByHeader: false,
  transpilePackages: ["@paylineage/ui", "@paylineage/canonical", "@paylineage/policy-runtime"],
  turbopack: { root: ROOT },
  // Same origin for the API so the session cookie stays SameSite=Strict.
  async rewrites() {
    return [{ source: "/v1/:path*", destination: `${API}/v1/:path*` }];
  },
};

export default config;
