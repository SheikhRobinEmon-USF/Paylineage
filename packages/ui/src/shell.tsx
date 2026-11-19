"use client";

import {
  Bot,
  Building2,
  FlaskConical,
  LayoutList,
  Moon,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Stamp,
  Sun,
} from "lucide-react";
import { type ComponentType, type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Badge, cx, Pill } from "./primitives";
import type { DataSource, Me, PolicyInfo, Queue } from "./types";

export type LinkLike = ComponentType<{ href: string; className?: string; children: ReactNode; "aria-current"?: "page" | undefined }>;

interface Env {
  source: DataSource;
  Link: LinkLike;
  navigate: (href: string) => void;
  pathname: string;
  me: Me | null;
  setMe: (m: Me | null) => void;
  policy: PolicyInfo | null;
  queue: Queue | null;
  refresh: () => void;
  version: number;
}

const EnvContext = createContext<Env | null>(null);

export function useEnv(): Env {
  const e = useContext(EnvContext);
  if (!e) throw new Error("useEnv outside EnvProvider");
  return e;
}

export function EnvProvider({ source, Link, navigate, pathname, children }: { source: DataSource; Link: LinkLike; navigate: (href: string) => void; pathname: string; children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [policy, setPolicy] = useState<PolicyInfo | null>(null);
  const [queue, setQueue] = useState<Queue | null>(null);
  const [version, setVersion] = useState(0);
  const refresh = useCallback(() => setVersion((v) => v + 1), []);
  useEffect(() => {
    let alive = true;
    void source.me().then((m) => alive && setMe(m)).catch(() => alive && setMe(null));
    void source.policy().then((p) => alive && setPolicy(p)).catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [source]);
  useEffect(() => {
    let alive = true;
    if (!me) return;
    void source.queue().then((q) => alive && setQueue(q)).catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [source, me, version]);
  const value = useMemo(() => ({ source, Link, navigate, pathname, me, setMe, policy, queue, refresh, version }), [source, Link, navigate, pathname, me, policy, queue, refresh, version]);
  return <EnvContext.Provider value={value}>{children}</EnvContext.Provider>;
}

const NAV = [
  { href: "/", label: "Payment Control", icon: LayoutList, q: "What needs me?" },
  { href: "/approvals", label: "Approval Center", icon: Stamp, q: "Am I approving exactly this?" },
  { href: "/suppliers", label: "Supplier Master", icon: Building2, q: "Is the supplier real?" },
  { href: "/agents", label: "Agent Authority", icon: Bot, q: "What can each agent do?" },
  { href: "/lab", label: "Attack Lab", icon: FlaskConical, q: "Does it hold up?" },
  { href: "/audit", label: "Audit Trail", icon: ScrollText, q: "Can I prove what happened?" },
];

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState("light");
  useEffect(() => {
    let t = "light";
    try {
      t = localStorage.getItem("pl-theme") ?? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    } catch {
      /* storage unavailable: default */
    }
    setTheme(t);
    document.documentElement.dataset.theme = t;
  }, []);
  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("pl-theme", next);
    } catch {
      /* ignore */
    }
  };
  return [theme, toggle];
}

function PolicyCard({ policy }: { policy: PolicyInfo | null }) {
  if (!policy) return <div className="text-[12px] text-muted">Loading policy…</div>;
  const ok = policy.runtime !== "unavailable";
  return (
    <div className="rounded-md border border-line bg-surface-2 p-2.5 text-[12px]">
      <div className="flex items-center gap-1.5 font-medium text-ink">
        {ok ? <ShieldCheck size={14} className="text-allow" aria-hidden /> : <ShieldAlert size={14} className="text-deny" aria-hidden />}
        Policy {ok ? "loaded" : "unavailable"}
      </div>
      <div className="mt-1 text-muted">
        Runtime <span className="num text-ink-2">{policy.runtime}</span>
      </div>
      <div className="text-muted">
        SHA-256 <span className="num text-ink-2" title={policy.sha256}>{policy.sha256.slice(0, 12)}…</span>
      </div>
      {policy.fallback_active && <div className="mt-1 font-medium text-hold-ink">OPA server fallback active</div>}
    </div>
  );
}

export function ModeBanner() {
  const { source } = useEnv();
  if (source.mode === "live") {
    return (
      <div className="border-b border-line bg-hold-soft/60 px-4 py-1.5 text-[12px] text-hold-ink">
        Simulation. Rails, bank accounts and supplier verification are simulated. All companies and people are fictional.
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface-2 px-4 py-1.5 text-[12px] text-ink-2">
      <span className="font-medium text-ink">Public demo, no backend.</span>
      <Badge kind="live" /> policy.wasm, RFC 8785 digests, permits and hash chain run in your browser.
      <Badge kind="replayed" /> extraction outputs and agent runs were recorded from the Python system.
      <Badge kind="simulated" /> rails, verification and passkeys.
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { Link, pathname, me, policy, queue, source } = useEnv();
  const [theme, toggleTheme] = useTheme();
  const counts: Record<string, number> = {
    "/": queue?.items.filter((i) => i.state === "held").length ?? 0,
    "/approvals": queue?.items.filter((i) => i.state === "awaiting_approval" || i.state === "approved").length ?? 0,
  };
  const policyDown = policy?.runtime === "unavailable";
  return (
    <div className="min-h-dvh bg-paper text-ink">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>
      <div className="flex min-h-dvh">
        <div className="hidden w-[236px] shrink-0 border-r border-line bg-surface lg:block">
        <aside className="sticky top-0 flex h-dvh flex-col px-3 py-4">
          <Link href="/" className="mb-5 block px-2">
            <div className="flex items-center gap-2">
              <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden>
                <rect x="2" y="2" width="20" height="20" rx="5" fill="var(--brand)" />
                <path d="M7 16V8h5a3 3 0 010 6H7" stroke="var(--brand-ink)" strokeWidth="2" fill="none" />
                <path d="M13 17h4" stroke="var(--brand-ink)" strokeWidth="2" />
              </svg>
              <span className="text-[15px] font-semibold tracking-tight">PayLineage</span>
            </div>
            <div className="mt-1 text-[11.5px] leading-4 text-muted">No payment leaves until the record matches.</div>
          </Link>
          <nav aria-label="Workspaces" className="flex flex-col gap-0.5">
            {NAV.map(({ href, label, icon: Icon, q }) => {
              const active = href === "/" ? pathname === "/" || pathname.startsWith("/case") : pathname.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  aria-current={active ? "page" : undefined}
                  className={cx(
                    "group flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] outline-none",
                    active ? "bg-brand-soft font-medium text-brand" : "text-ink-2 hover:bg-surface-2",
                  )}
                >
                  <Icon size={16} aria-hidden />
                  <span className="flex-1">
                    {label}
                    <span className="sr-only">: {q}</span>
                  </span>
                  {(counts[href] ?? 0) > 0 && <span className="num rounded bg-surface-3 px-1.5 text-[11px] text-ink-2">{counts[href]}</span>}
                </Link>
              );
            })}
          </nav>
          <div className="mt-auto flex flex-col gap-3">
            <PolicyCard policy={policy} />
            <div className="flex items-center justify-between px-1 text-[12px]">
              <div className="min-w-0">
                <div className="truncate font-medium text-ink">{me?.name ?? "Signed out"}</div>
                <div className="truncate text-muted">{me?.roles.join(", ").replace(/_/g, " ")}</div>
              </div>
              <button type="button" onClick={toggleTheme} className="rounded p-1.5 text-ink-2 hover:bg-surface-2" aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
                {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
              </button>
            </div>
          </div>
        </aside>
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex items-center gap-3 border-b border-line bg-surface px-4 py-2 lg:hidden">
            <span className="font-semibold">PayLineage</span>
            <nav aria-label="Workspaces" className="flex gap-1 overflow-x-auto">
              {NAV.map((n) => (
                <Link key={n.href} href={n.href} className="whitespace-nowrap rounded px-2 py-1 text-[12px] text-ink-2 hover:bg-surface-2">
                  {n.label}
                </Link>
              ))}
            </nav>
          </header>
          <ModeBanner />
          {policyDown && (
            <div role="alert" className="border-b border-deny/30 bg-deny-soft px-4 py-2 text-[13px] font-medium text-deny">
              Policy unavailable. Every decision is deny until a verified policy.wasm loads. Nothing can be approved or paid.
            </div>
          )}
          <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-5 lg:px-6">
            {children}
          </main>
          <footer className="border-t border-line px-6 py-3 text-[11.5px] text-muted">
            PayLineage {source.mode === "demo" ? "public demo" : "simulation"}. Supplier verification is simulated: PayLineage enforces verification decisions, it does not prove real bank account ownership.{" "}
            <Pill className="ml-1">fictional data</Pill>
          </footer>
        </div>
      </div>
    </div>
  );
}

export function PageHeader({ title, question, actions }: { title: string; question: string; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight">{title}</h1>
        <p className="text-[13px] text-muted">{question}</p>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
