"use client";

import { ShieldCheck, ShieldX } from "lucide-react";
import { useEffect, useState } from "react";
import { when } from "./format";
import { Banner, Button, Digest, Panel, Pill } from "./primitives";
import { PageHeader, useEnv } from "./shell";
import type { AuditView } from "./types";

export function AuditTrail() {
  const { source, version } = useEnv();
  const [a, setA] = useState<AuditView | null>(null);
  const load = () => void source.audit().then(setA);
  useEffect(load, [source, version]);
  return (
    <div>
      <PageHeader title="Audit Trail" question="Can I prove what happened? A hash chain with signed checkpoints outside the database." actions={<Button onPress={load}>Verify again</Button>} />
      {a && (
        <div className="mb-3">
          {a.verified ? (
            <Banner tone="allow" icon={<ShieldCheck size={15} aria-hidden />}>Chain verified: {a.events.length} events, every hash recomputes and links. {a.note}</Banner>
          ) : (
            <Banner tone="deny" icon={<ShieldX size={15} aria-hidden />}>Tampering detected: {a.problems.map((p) => `#${p.seq} ${p.kind}`).join(", ")}</Banner>
          )}
          <div className="mt-2 text-[12px] text-muted">Head <Digest value={a.head} short /></div>
        </div>
      )}
      <Panel dense title="Events, newest first">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="border-b border-line text-left text-[11.5px] text-muted">
              <th scope="col" className="px-3 py-2 font-medium">#</th>
              <th scope="col" className="px-3 py-2 font-medium">Event</th>
              <th scope="col" className="px-3 py-2 font-medium">Actor</th>
              <th scope="col" className="px-3 py-2 font-medium">When</th>
              <th scope="col" className="px-3 py-2 font-medium">Hash</th>
            </tr>
          </thead>
          <tbody>
            {[...(a?.events ?? [])].reverse().slice(0, 300).map((e) => (
              <tr key={e.seq} className="border-b border-line last:border-0">
                <td className="num px-3 py-1.5 text-muted">{e.seq}</td>
                <td className="px-3 py-1.5"><Pill tone={e.kind.startsWith("supplier.") ? "brand" : e.kind.includes("refused") || e.kind.includes("denied") ? "deny" : "neutral"}>{e.kind}</Pill></td>
                <td className="px-3 py-1.5">{e.actor}</td>
                <td className="num px-3 py-1.5 text-muted">{when(e.at)}</td>
                <td className="num px-3 py-1.5 text-muted">{e.hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <p className="mt-2 text-[11.5px] text-muted">Tamper evident, not tamper proof: the log proves the integrity of what was recorded relative to the last signed checkpoint, not that the recorded facts were true.</p>
    </div>
  );
}
