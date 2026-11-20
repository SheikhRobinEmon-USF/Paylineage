"use client";

import { Fingerprint, UserRound } from "lucide-react";
import { useEffect, useState } from "react";
import { Banner, Button, Panel, Pill } from "./primitives";
import { useEnv } from "./shell";
import type { Persona } from "./types";

const ORDER = ["fin1", "ana1", "ap1", "stw1", "ver1", "eng1"];

export function SignIn() {
  const { source, setMe, refresh } = useEnv();
  const [people, setPeople] = useState<Persona[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    void source.personas().then((p) => setPeople([...p].sort((a, b) => (ORDER.indexOf(a.handle) + 99) % 99 - (ORDER.indexOf(b.handle) + 99) % 99)));
  }, [source]);
  return (
    <div className="mx-auto mt-10 max-w-2xl">
      <h1 className="text-[22px] font-semibold tracking-tight">Sign in to PayLineage</h1>
      <p className="mt-1 text-[13px] text-muted">No payment leaves until the record matches. Choose a fictional person to see the workspaces through their role.</p>
      <div className="mt-4">
        <Banner tone="hold">{source.mode === "demo" ? "Simulated sign in. This demo runs entirely in your browser." : "Development persona switch. Approvals still require that person's passkey; nothing here bypasses it."}</Banner>
      </div>
      {err && <div className="mt-3"><Banner tone="deny">{err}</Banner></div>}
      <Panel className="mt-4" dense>
        <ul className="divide-y divide-line">
          {people.map((p) => (
            <li key={p.handle} className="flex items-center justify-between gap-3 px-4 py-2.5">
              <div className="flex items-center gap-3">
                <UserRound size={18} className="text-muted" aria-hidden />
                <div>
                  <div className="text-[13.5px] font-medium">{p.name}</div>
                  <div className="mt-0.5 flex gap-1">{p.roles.map((r) => <Pill key={r}>{r.replace(/_/g, " ")}</Pill>)}</div>
                </div>
              </div>
              <Button variant="primary" onPress={async () => { try { setMe(await source.signInAs(p.handle)); refresh(); } catch (e) { setErr((e as Error).message); } }}>Continue as {p.name.split(" ")[0]}</Button>
            </li>
          ))}
        </ul>
      </Panel>
      <p className="mt-3 flex items-center gap-1.5 text-[12px] text-muted"><Fingerprint size={14} aria-hidden /> Real sign in uses passkeys (WebAuthn, user verification required, origin checked).</p>
    </div>
  );
}

export function PasskeyEnroll() {
  const { source, me, setMe } = useEnv();
  const [state, setState] = useState<"idle" | "busy" | "done" | "error">("idle");
  if (!me || (me.passkeys ?? 1) > 0 || source.mode === "demo") return null;
  return (
    <div className="mb-3">
      <Banner tone="brand" icon={<Fingerprint size={15} aria-hidden />}>
        <div className="flex flex-wrap items-center gap-3">
          <span>{me.name} has no passkey yet. Approvals need one.</span>
          <Button variant="primary" isDisabled={state === "busy"} onPress={async () => {
            setState("busy");
            try {
              await source.registerPasskey();
              setState("done");
              setMe({ ...me, passkeys: 1 });
            } catch {
              setState("error");
            }
          }}>Create passkey</Button>
          {state === "error" && <span className="text-deny">Passkey creation failed or was cancelled.</span>}
        </div>
      </Banner>
    </div>
  );
}
