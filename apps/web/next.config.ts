import path from "node:path";
import type { NextConfig } from "next";

const API = process.env.PAYLINEAGE_API_URL ?? "http://localhost:8000";

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  transpilePackages: ["@paylineage/ui", "@paylineage/canonical", "@paylineage/policy-runtime"],
  turbopack: { root: path.join(import.meta.dirname, "../..") },
  // Same origin for the API so the session cookie stays SameSite=Strict.
  async rewrites() {
    return [{ source: "/v1/:path*", destination: `${API}/v1/:path*` }];
  },
};

export default config;
