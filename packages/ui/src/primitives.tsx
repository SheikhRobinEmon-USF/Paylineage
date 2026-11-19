"use client";

import { clsx } from "clsx";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleDashed,
  Clock,
  FileWarning,
  Hourglass,
  KeyRound,
  ShieldCheck,
  Stamp,
} from "lucide-react";
import type { ReactNode } from "react";
import { Button as AriaButton, type ButtonProps, Tooltip, TooltipTrigger } from "react-aria-components";
import { STATE_LABEL, chunk, humanize, money } from "./format";
import type { Decision, PaymentState } from "./types";

export function cx(...a: Parameters<typeof clsx>): string {
  return clsx(...a);
}

const TONE = {
  allow: "bg-allow-soft text-allow border-allow/30",
  hold: "bg-hold-soft text-hold-ink border-hold/40",
  deny: "bg-deny-soft text-deny border-deny/30",
  neutral: "bg-surface-2 text-ink-2 border-line",
  brand: "bg-brand-soft text-brand border-brand/30",
  untrusted: "bg-untrusted-soft text-untrusted border-untrusted/30",
} as const;
export type Tone = keyof typeof TONE;

export function Pill({ tone = "neutral", icon, children, className }: { tone?: Tone; icon?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[12px] font-medium leading-4 whitespace-nowrap", TONE[tone], className)}>
      {icon}
      {children}
    </span>
  );
}

const STATE_TONE: Record<PaymentState, Tone> = {
  proposed: "neutral",
  evaluated: "neutral",
  held: "hold",
  denied: "deny",
  awaiting_approval: "brand",
  approved: "brand",
  permit_issued: "brand",
  executed: "allow",
  expired: "neutral",
};

const STATE_ICON: Record<PaymentState, ReactNode> = {
  proposed: <CircleDashed size={13} aria-hidden />,
  evaluated: <CircleDashed size={13} aria-hidden />,
  held: <AlertTriangle size={13} aria-hidden />,
  denied: <Ban size={13} aria-hidden />,
  awaiting_approval: <Hourglass size={13} aria-hidden />,
  approved: <Stamp size={13} aria-hidden />,
  permit_issued: <KeyRound size={13} aria-hidden />,
  executed: <CheckCircle2 size={13} aria-hidden />,
  expired: <Clock size={13} aria-hidden />,
};

/** Status = word + icon + color. Never color alone. */
export function StateBadge({ state }: { state: PaymentState }) {
  return (
    <Pill tone={STATE_TONE[state]} icon={STATE_ICON[state]}>
      {STATE_LABEL[state] ?? state}
    </Pill>
  );
}

export function DecisionBadge({ decision }: { decision: Decision | null | undefined }) {
  if (!decision) return <Pill>No decision</Pill>;
  const map: Record<Decision, [Tone, ReactNode, string]> = {
    allow: ["allow", <ShieldCheck size={13} aria-hidden key="i" />, "Allowed"],
    hold: ["hold", <AlertTriangle size={13} aria-hidden key="i" />, "Hold"],
    deny: ["deny", <Ban size={13} aria-hidden key="i" />, "Denied"],
  };
  const [tone, icon, label] = map[decision];
  return (
    <Pill tone={tone} icon={icon}>
      {label}
    </Pill>
  );
}

export function ReasonChip({ code, cls, meaning }: { code: string; cls?: "deny" | "hold" | undefined; meaning?: string | undefined }) {
  const tone: Tone = code.startsWith("SIGNAL_") ? "untrusted" : cls === "deny" ? "deny" : cls === "hold" ? "hold" : "neutral";
  const chip = (
    <Pill tone={tone} className="font-mono text-[11px]" icon={code.startsWith("SIGNAL_") ? <FileWarning size={12} aria-hidden /> : undefined}>
      {code}
    </Pill>
  );
  if (!meaning) return chip;
  return (
    <TooltipTrigger delay={300}>
      <AriaButton className="cursor-help rounded-md outline-none">{chip}</AriaButton>
      <Tooltip className="max-w-xs rounded-md border border-line bg-surface px-2 py-1 text-xs text-ink shadow-card" offset={6}>
        {humanize(code)}: {meaning}
      </Tooltip>
    </TooltipTrigger>
  );
}

export function Money({ minor, currency = "USD", className }: { minor: number; currency?: string; className?: string }) {
  return <span className={cx("num whitespace-nowrap", className)}>{money(minor, currency)}</span>;
}

export function Digest({ value, short = false, label = "SHA-256" }: { value: string; short?: boolean; label?: string }) {
  if (short) {
    return (
      <span className="num text-xs text-ink-2" title={value} aria-label={`${label} ${value}`}>
        {value.slice(0, 12)}…
      </span>
    );
  }
  return (
    <span className="num inline-flex flex-wrap gap-x-1.5 text-[12.5px] leading-5 text-ink" aria-label={`${label} ${value}`}>
      {chunk(value).map((c, i) => (
        <span key={i} className={i % 2 ? "text-ink-2" : "text-ink"}>
          {c}
        </span>
      ))}
    </span>
  );
}

/** A value whose origin is untrusted_external and not matched to the master. */
export function Untrusted({ children, why }: { children: ReactNode; why?: string | undefined }) {
  return (
    <span className="untrusted" title={why ?? "Untrusted origin: from an email or invoice, not matched to a verified record"}>
      {children}
      <span className="sr-only"> (untrusted origin)</span>
    </span>
  );
}

export function Panel({ title, actions, children, className, dense = false }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; dense?: boolean }) {
  return (
    <section className={cx("rounded-lg border border-line bg-surface shadow-card", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-2.5">
          <h2 className="text-[13px] font-semibold tracking-tight text-ink">{title}</h2>
          {actions}
        </header>
      )}
      <div className={dense ? "" : "p-4"}>{children}</div>
    </section>
  );
}

type Variant = "primary" | "secondary" | "danger" | "ghost";
const VARIANT: Record<Variant, string> = {
  primary: "bg-brand text-brand-ink border-brand hover:opacity-95",
  secondary: "bg-surface text-ink border-line-strong hover:bg-surface-2",
  danger: "bg-surface text-deny border-deny/40 hover:bg-deny-soft",
  ghost: "bg-transparent text-ink-2 border-transparent hover:bg-surface-2",
};

export function Button({ variant = "secondary", className, ...p }: ButtonProps & { variant?: Variant; className?: string }) {
  return (
    <AriaButton
      {...p}
      className={cx(
        "inline-flex h-8 items-center gap-1.5 rounded-md border px-3 text-[13px] font-medium outline-none transition-colors",
        "data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 data-[pressed]:translate-y-px",
        "data-[focus-visible]:outline-2 data-[focus-visible]:outline-offset-2 data-[focus-visible]:outline-focus",
        VARIANT[variant],
        className,
      )}
    />
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="num rounded border border-line-strong bg-surface-2 px-1 text-[11px] text-ink-2">{children}</kbd>;
}

export function Banner({ tone = "neutral", icon, children }: { tone?: Tone; icon?: ReactNode; children: ReactNode }) {
  return (
    <div role="status" className={cx("flex items-start gap-2 rounded-md border px-3 py-2 text-[13px]", TONE[tone])}>
      {icon}
      <div>{children}</div>
    </div>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: Tone }) {
  return (
    <div className="min-w-0 rounded-lg border border-line bg-surface px-4 py-3 shadow-card">
      <div className="text-[12px] font-medium text-muted">{label}</div>
      <div className={cx("num mt-1 text-[22px] font-medium tracking-tight", tone === "hold" && "text-hold-ink", tone === "deny" && "text-deny", tone === "allow" && "text-allow")}>{value}</div>
      {hint && <div className="mt-0.5 text-[12px] text-muted">{hint}</div>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1 px-6 py-12 text-center">
      <div className="text-sm font-medium text-ink">{title}</div>
      {children && <div className="max-w-md text-[13px] text-muted">{children}</div>}
    </div>
  );
}

export function Badge({ kind }: { kind: "valid" | "trusted" | "simulated" | "replayed" | "live" }) {
  const t: Record<typeof kind, [Tone, string]> = {
    valid: ["brand", "valid: the math checks out"],
    trusted: ["allow", "trusted: verified by the server"],
    simulated: ["hold", "simulated"],
    replayed: ["untrusted", "replayed recording"],
    live: ["allow", "live in this browser"],
  };
  return <Pill tone={t[kind][0]}>{t[kind][1]}</Pill>;
}
