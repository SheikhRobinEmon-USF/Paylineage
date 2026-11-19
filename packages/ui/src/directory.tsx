"use client";

import { Bot, KeyRound, UserCheck, Users } from "lucide-react";
import { useEffect, useState } from "react";
import { Dialog, DialogTrigger, Heading, Modal, ModalOverlay } from "react-aria-components";
import { compactMoney, when } from "./format";
import { Banner, Button, Empty, Panel, Pill, cx } from "./primitives";
import { PageHeader, useEnv } from "./shell";
import type { AgentView, MandateView, SupplierView } from "./types";

export function SupplierMaster() {
  const { source, version } = useEnv();
  const [rows, setRows] = useState<SupplierView[] | null>(null);
  useEffect(() => {
    void source.suppliers().then(setRows);
  }, [source, version]);
  return (
    <div>
      <PageHeader title="Supplier Master" question="Is the supplier real? Verified records, bank accounts and who changed them." />
      <div className="mb-3"><Banner tone="hold">Verification is simulated. PayLineage enforces who may verify and with what evidence; it does not prove real bank account ownership.</Banner></div>
      {!rows ? <div className="text-[13px] text-muted">Loading…</div> : rows.length === 0 ? <Empty title="No suppliers" /> : (
        <div className="grid gap-4 xl:grid-cols-2">
          {rows.map((s) => (
            <Panel key={s.id} title={s.legal_name} actions={<Pill tone={s.status === "verified" ? "allow" : s.status === "rejected" ? "deny" : "hold"}>{s.status}</Pill>}>
              <dl className="grid grid-cols-[130px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
                <dt className="text-muted">Verified domains</dt><dd className="num">{s.verified_domains.join(", ") || "none yet"}</dd>
                <dt className="text-muted">Registry</dt><dd className="num">{s.registry_id ?? "none"}</dd>
                <dt className="text-muted">Contact on file</dt><dd>{s.contact_on_file ? `${s.contact_on_file["name"] ?? ""} ${s.contact_on_file["phone"] ?? ""}` : "none"} <span className="text-muted">{s.contact_recorded_at ? `recorded ${when(s.contact_recorded_at)}` : ""}</span></dd>
              </dl>
              <h3 className="mt-3 text-[12px] font-semibold text-ink-2">Bank accounts</h3>
              <ul className="mt-1 flex flex-col gap-1">
                {s.accounts.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-2 text-[12.5px]">
                    <span className="num">{a.masked}</span>
                    <Pill tone={a.status === "verified" ? "allow" : a.status === "pending" ? "hold" : "deny"}>{a.status}</Pill>
                    <span className="text-muted">{a.bank_name}</span>
                    {a.cooling_off_until && <span className="text-hold-ink">cooling-off until {when(a.cooling_off_until)}</span>}
                  </li>
                ))}
              </ul>
              {s.requests.length > 0 && (
                <>
                  <h3 className="mt-3 text-[12px] font-semibold text-ink-2">Changes and separation of duties</h3>
                  <ul className="mt-1 flex flex-col gap-2">
                    {s.requests.map((r) => {
                      const people = [r.requester, r.verifier, r.steward].filter(Boolean);
                      const distinct = new Set(people).size === people.length;
                      return (
                        <li key={r.id} className="rounded-md border border-line p-2 text-[12.5px]">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium">{r.kind === "bank_change" ? "Bank change" : "New supplier"}</span>
                            <Pill tone={r.state === "verified" ? "allow" : r.state === "rejected" ? "deny" : "hold"}>{r.state.replace("_", " ")}</Pill>
                            <span className="text-muted">via {r.channel}, risk {r.risk_tier}</span>
                          </div>
                          <div className="mt-1 flex flex-wrap gap-1.5">
                            <Pill icon={<Users size={12} aria-hidden />}>Requested: {r.requester ?? "?"}</Pill>
                            <Pill icon={<UserCheck size={12} aria-hidden />}>Verified: {r.verifier ?? "unassigned"}</Pill>
                            <Pill icon={<KeyRound size={12} aria-hidden />}>Steward: {r.steward ?? "pending"}</Pill>
                            {people.length > 1 && <Pill tone={distinct ? "allow" : "deny"}>{distinct ? "distinct people" : "SoD conflict"}</Pill>}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </>
              )}
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}

const MANDATE_FIELDS: [keyof MandateView, string, (v: unknown) => string][] = [
  ["per_proposal_ceiling_minor", "Per proposal ceiling", (v) => compactMoney(Number(v))],
  ["daily_ceiling_minor", "Daily ceiling", (v) => compactMoney(Number(v))],
  ["second_approver_above_minor", "Second approver above", (v) => compactMoney(Number(v))],
  ["supplier_scope", "Supplier scope", (v) => ((v as string[]).includes("*") ? "all suppliers" : `${(v as string[]).length} suppliers`)],
  ["permitted_operations", "Permitted", (v) => (v as string[]).join(", ")],
  ["forbidden_operations", "Forbidden", (v) => (v as string[]).join(", ")],
  ["approver_role", "Approver role", (v) => String(v).replace(/_/g, " ")],
  ["expires_at", "Expires", (v) => when(v as string)],
  ["revoked_at", "Revoked", (v) => (v ? when(v as string) : "no")],
];

export function AgentAuthority() {
  const { source, version, refresh, me } = useEnv();
  const [agents, setAgents] = useState<AgentView[] | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    void source.agents().then(setAgents);
  }, [source, version]);
  const canRevoke = me?.roles.some((r) => r === "platform_engineer" || r === "admin") ?? false;
  return (
    <div>
      <PageHeader title="Agent Authority" question="What can each agent do? Keys, versioned mandates and revocation." />
      {msg && <div className="mb-3"><Banner tone="allow">{msg}</Banner></div>}
      {!agents ? <div className="text-[13px] text-muted">Loading…</div> : agents.map((a) => {
        const cur = a.mandates[0];
        const prev = a.mandates[1];
        return (
          <Panel key={a.id} className="mb-4" title={<span className="flex items-center gap-2"><Bot size={15} aria-hidden /> {a.display_name} <span className="num text-muted">{a.id}</span></span>} actions={<Pill tone={a.active ? "allow" : "deny"}>{a.active ? "active" : "inactive"}</Pill>}>
            <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
              <div>
                <div className="text-[12px] font-semibold text-ink-2">Request signing</div>
                <p className="mt-1 text-[12.5px] text-muted">HTTP Message Signatures (RFC 9421), Ed25519, with Content-Digest and a single use nonce.</p>
                <div className="mt-2 text-[12px]">Key id <span className="num">{a.key_id}</span></div>
                <div className="num mt-1 break-all text-[11.5px] text-muted">{a.public_key_hex}</div>
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <div className="text-[12px] font-semibold text-ink-2">Mandate v{cur?.version}{prev ? `, changes since v${prev.version}` : ""}</div>
                  {canRevoke && cur && !cur.revoked_at && <Button variant="danger" onPress={() => setConfirm(a.id)}>Revoke mandate</Button>}
                </div>
                <table className="mt-2 w-full text-[12.5px]">
                  <tbody>
                    {cur && MANDATE_FIELDS.map(([k, label, fmt]) => {
                      const now = fmt(cur[k]);
                      const was = prev ? fmt(prev[k]) : null;
                      const changed = was !== null && was !== now;
                      return (
                        <tr key={k} className="border-b border-line last:border-0">
                          <th scope="row" className="w-44 py-1 pr-2 text-left font-normal text-muted">{label}</th>
                          <td className={cx("py-1", changed && "font-medium")}>
                            {now}
                            {changed && <span className="ml-2 text-[11.5px] text-muted line-through">{was}</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <p className="mt-2 text-[11.5px] text-muted">Loaded only from the trusted store by agent and version. A mandate in a request body is ignored. Agents can never change bank details, approve, execute or edit mandates.</p>
              </div>
            </div>
          </Panel>
        );
      })}
      <DialogTrigger isOpen={confirm !== null} onOpenChange={(o) => !o && setConfirm(null)}>
        <span />
        <ModalOverlay className="fixed inset-0 z-40 grid place-items-center bg-ink/30 p-4">
          <Modal className="w-full max-w-md rounded-lg border border-line bg-surface p-5 shadow-card">
            <Dialog className="outline-none" role="alertdialog">
              <Heading slot="title" className="text-[15px] font-semibold">Revoke the mandate for {confirm}?</Heading>
              <p className="mt-2 text-[13px] text-ink-2">Every proposal under this mandate loses execution eligibility immediately, including approved payments with valid signatures. This cannot be undone; a new version must be issued.</p>
              <div className="mt-4 flex justify-end gap-2">
                <Button onPress={() => setConfirm(null)}>Cancel</Button>
                <Button variant="danger" onPress={async () => { if (confirm) { await source.revokeMandate(confirm, "Revoked from Agent Authority"); setMsg("Mandate revoked. Try executing an approved payment to see revalidation refuse it."); setConfirm(null); refresh(); } }}>Revoke</Button>
              </div>
            </Dialog>
          </Modal>
        </ModalOverlay>
      </DialogTrigger>
    </div>
  );
}
