import path from "node:path";
import type { NextConfig } from "next";

// GitHub Pages serves the site under /<repo>. Set NEXT_PUBLIC_BASE_PATH=/Paylineage in CI.
const base = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const config: NextConfig = {
  output: "export",
  basePath: base,
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
  transpilePackages: ["@paylineage/ui", "@paylineage/canonical", "@paylineage/policy-runtime"],
  turbopack: { root: path.join(import.meta.dirname, "../..") },
};

export default config;
