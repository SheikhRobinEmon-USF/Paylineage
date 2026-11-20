import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "PayLineage demo",
  description: "Public demo: the real policy.wasm, canonical digests, permits and a hash chain, running in your browser. Simulation only.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" data-theme="light">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
