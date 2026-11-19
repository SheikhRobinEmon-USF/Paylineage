"use client";

import { AppShell, EnvProvider, type LinkLike, SignIn, useEnv } from "@paylineage/ui";
import NextLink from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { type ReactNode, useState } from "react";
import type { DataSource } from "@paylineage/ui";
import { DemoEngine, ssrStub } from "../engine";

const Link: LinkLike = ({ href, className, children, ...rest }) => (
  <NextLink href={href} className={className} {...rest}>
    {children}
  </NextLink>
);

function Gate({ children }: { children: ReactNode }) {
  const { me } = useEnv();
  return me ? <>{children}</> : <SignIn />;
}

export function Providers({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [source] = useState<DataSource>(() => (typeof window === "undefined" ? ssrStub : new DemoEngine()));
  return (
    <EnvProvider source={source} Link={Link} navigate={(h) => router.push(h)} pathname={pathname}>
      <AppShell>
        <Gate>{children}</Gate>
      </AppShell>
    </EnvProvider>
  );
}
