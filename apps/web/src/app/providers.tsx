"use client";

import { AppShell, EnvProvider, type LinkLike, PasskeyEnroll, SignIn, useEnv } from "@paylineage/ui";
import NextLink from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { liveSource } from "@/lib/live-source";

const Link: LinkLike = ({ href, className, children, ...rest }) => (
  <NextLink href={href} className={className} {...rest}>
    {children}
  </NextLink>
);

function Gate({ children }: { children: ReactNode }) {
  const { me } = useEnv();
  if (!me) return <SignIn />;
  return (
    <>
      <PasskeyEnroll />
      {children}
    </>
  );
}

export function Providers({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  return (
    <EnvProvider source={liveSource} Link={Link} navigate={(h) => router.push(h)} pathname={pathname}>
      <AppShell>
        <Gate>{children}</Gate>
      </AppShell>
    </EnvProvider>
  );
}
