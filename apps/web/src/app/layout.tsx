import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { Providers } from "./providers";

// Rendered per request so Next can stamp the CSP nonce from proxy.ts onto its scripts.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "PayLineage",
  description: "Stops AI accounts payable agents from paying unverified or unauthorized beneficiaries. Simulation only.",
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
