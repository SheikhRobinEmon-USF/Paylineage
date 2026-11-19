"use client";

import { Background, type Edge, MarkerType, type Node, Position, ReactFlow } from "@xyflow/react";
import { ArrowLeft, Bot, EyeOff, Mail, RefreshCw, ShieldAlert, Sparkles, Stamp } from "lucide-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { Label, ListBox, ListBoxItem, Popover, Select, SelectValue, Button as AriaButton, TextArea, TextField } from "react-aria-components";
import { FIELD_LABEL, SOURCE_LABEL, STATE_LABEL, humanize, when } from "./format";
import { Banner, Button, DecisionBadge, Digest, Empty, Money, Panel, Pill, ReasonChip, StateBadge, Untrusted, cx } from "./primitives";
import { useEnv } from "./shell";
import { ApiError, type FieldFact, type PaymentDetail } from "./types";

const CLEARABLE = new Set(["DUPLICATE_INVOICE", "SIGNAL_DMARC_FAIL", "SIGNAL_HIDDEN_TEXT", "SIGNAL_LOOKALIKE_DOMAIN", "SIGNAL_PROMPT_INJECTION", "SIGNAL_REPLY_TO_MISMATCH", "SIGNAL_TOOL_POISONING"]);

function useCase(id: string | null) {
  const { source, version } = useEnv();
  const [data, setData] = useState<PaymentDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!id) return;
    let alive = true;
    source.payment(id).then((d) => alive && setData(d)).catch((e: Error) => alive && setErr(e.message));
    return () => {
      alive = false;
    };
  }, [id, source, version]);
  return { data, err };
}

function trustNode(f: FieldFact | undefined): string {
  if (!f) return "var(--line-strong)";
  if (f.source_kind === "agent_asserted") return "var(--deny)";
  if (f.trust_class !== "untrusted_external" || f.master_matched) return "var(--allow)";
  return "var(--untrusted)";
}

function Lineage({ d }: { d: PaymentDetail }) {
  const byName = new Map(d.fields.map((f) => [f.field_name, f]));
  const fields = ["beneficiary_account", "amount", "supplier_name", "currency"];
  const lr = { sourcePosition: Position.Right, targetPosition: Position.Left };
  const nodes: Node[] = [
    { id: "email", position: { x: 0, y: 66 }, data: { label: `Email\n${String(d.email?.transport["from_domain"] ?? "unknown")}` }, style: box("var(--untrusted)"), ...lr },
    { id: "doc", position: { x: 190, y: 66 }, data: { label: `Attachment\n${d.document.filename ?? "body"}` }, style: box("var(--untrusted)"), ...lr },
    ...fields.map((f, i): Node => ({ id: f, position: { x: 380, y: i * 46 }, data: { label: FIELD_LABEL[f] ?? f }, style: box(trustNode(byName.get(f))), ...lr })),
    { id: "master", position: { x: 570, y: 20 }, data: { label: `Supplier master\n${d.supplier?.status ?? "no record"}` }, style: box("var(--allow)"), ...lr },
    { id: "po", position: { x: 570, y: 112 }, data: { label: "Purchase order\nentered by a person" }, style: box("var(--allow)"), ...lr },
    { id: "policy", position: { x: 760, y: 66 }, data: { label: `Policy: ${d.decision ?? "none"}\n${d.reasons.length} reason${d.reasons.length === 1 ? "" : "s"}` }, style: box(d.decision === "allow" ? "var(--allow)" : d.decision === "deny" ? "var(--deny)" : "var(--hold)"), ...lr },
  ];
  const edge = (id: string, s: string, t: string, ok: boolean | null, label?: string): Edge => ({
    id, source: s, target: t, label, animated: false, markerEnd: { type: MarkerType.ArrowClosed },
    style: { stroke: ok === null ? "var(--line-strong)" : ok ? "var(--allow)" : "var(--deny)", strokeDasharray: ok === false ? "4 3" : undefined, strokeWidth: 1.5 },
    labelStyle: { fontSize: 10, fill: "var(--muted)" }, labelBgStyle: { fill: "var(--surface)" },
  });
  const edges: Edge[] = [
    edge("e1", "email", "doc", null),
    ...fields.map((f) => edge(`x-${f}`, "doc", f, byName.get(f)?.consistency === "consistent" ? null : false, byName.get(f)?.consistency === "inconsistent" ? "span fails" : undefined)),
    edge("m1", "beneficiary_account", "master", byName.get("beneficiary_account")?.master_matched ?? false, byName.get("beneficiary_account")?.master_matched ? "matches" : "no match"),
    edge("m2", "supplier_name", "master", byName.get("supplier_name")?.master_matched ?? false),
    edge("m3", "amount", "po", byName.get("amount")?.master_matched ?? false, byName.get("amount")?.master_matched ? "= PO" : "≠ PO"),
    edge("m4", "currency", "po", byName.get("currency")?.master_matched ?? false),
    edge("p1", "master", "policy", null),
    edge("p2", "po", "policy", null),
  ];
  return (
    <div className="h-[240px] rounded-md border border-line bg-surface-2" aria-label="Data lineage from email to decision" role="img">
      <ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.06 }} nodesDraggable={false} nodesConnectable={false} elementsSelectable={false} panOnDrag={false} zoomOnScroll={false} proOptions={{ hideAttribution: true }}>
        <Background gap={16} size={1} color="var(--line)" />
      </ReactFlow>
    </div>
  );
}

function box(color: string): Record<string, string | number> {
  return { border: `1.5px solid ${color}`, borderRadius: 6, background: "var(--surface)", color: "var(--ink)", fontSize: 11.5, lineHeight: "15px", fontFamily: "IBM Plex Sans", whiteSpace: "pre-line", width: 160, padding: "5px 8px" };
}

function InvoiceViewer({ d, focus }: { d: PaymentDetail; focus: string | null }) {
  const quotes = new Map(d.extracted.map((e) => [e.field, e.quote ?? ""]));
  const focusQuote = focus ? quotes.get(focus) : undefined;
  const page = d.document.pages[0];
  const hidden = d.document.pages.map((p) => p.hidden).filter(Boolean).join("\n");
  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-md border border-line bg-surface-2 p-4">
        <div className="mb-2 flex items-center justify-between text-[11.5px] text-muted">
          <span>{d.document.filename ?? "Email body"}, page 1, as a person sees it</span>
          <Pill tone="untrusted">untrusted_external</Pill>
        </div>
        <div className="num whitespace-pre-wrap text-[12.5px] leading-6 text-ink">
          {(page?.text ?? d.email?.body ?? "").split("\n").map((line, i) => {
            const hit = [...quotes.entries()].find(([, q]) => q && line.includes(q.trim()))?.[0];
            const on = focusQuote && line.includes(focusQuote.trim());
            return (
              <div key={i} className={cx("rounded px-1", on ? "bg-brand-soft ring-1 ring-brand" : hit ? "bg-surface" : "")}>
                {line || " "}
                {hit && <span className="ml-2 align-middle text-[10px] text-muted">[{FIELD_LABEL[hit] ?? hit}]</span>}
              </div>
            );
          })}
        </div>
      </div>
      {hidden && (
        <div className="rounded-md border border-deny/40 bg-deny-soft p-3" role="note">
          <div className="mb-1 flex items-center gap-1.5 text-[12px] font-semibold text-deny">
            <EyeOff size={14} aria-hidden /> Hidden from human readers (white or tiny text in the PDF)
          </div>
          <div className="num whitespace-pre-wrap text-[12px] text-ink">{hidden}</div>
          <div className="mt-1 text-[11.5px] text-muted">Shown as text only. It was sent to signals, never to the extractor or the agent.</div>
        </div>
      )}
    </div>
  );
}

function FieldsTable({ d, setFocus }: { d: PaymentDetail; setFocus: (f: string | null) => void }) {
  const extracted = new Map(d.extracted.map((e) => [e.field, e]));
  return (
    <table className="w-full text-[12.5px]">
      <thead>
        <tr className="border-b border-line text-left text-[11.5px] text-muted">
          <th scope="col" className="py-1.5 pr-2 font-medium">Field</th>
          <th scope="col" className="py-1.5 pr-2 font-medium">Value</th>
          <th scope="col" className="py-1.5 pr-2 font-medium">Source</th>
          <th scope="col" className="py-1.5 pr-2 font-medium">Span</th>
          <th scope="col" className="py-1.5 font-medium">Master</th>
        </tr>
      </thead>
      <tbody>
        {d.fields.map((f) => {
          const ex = extracted.get(f.field_name);
          const untrusted = f.trust_class === "untrusted_external" && !f.master_matched;
          const val = f.field_name === "amount" ? <Money minor={d.amount_minor} currency={d.currency} /> : f.field_name === "beneficiary_account" ? <span className="num">{d.proposed_account.masked}</span> : f.field_name === "supplier_name" ? (d.supplier?.legal_name ?? ex?.display ?? "") : f.field_name === "currency" ? d.currency : (ex?.display ?? "system record");
          return (
            <tr key={f.field_name} className="border-b border-line last:border-0 align-top" onMouseEnter={() => setFocus(f.field_name)} onMouseLeave={() => setFocus(null)} onFocus={() => setFocus(f.field_name)} tabIndex={0}>
              <td className="py-2 pr-2 font-medium">{FIELD_LABEL[f.field_name] ?? f.field_name}</td>
              <td className="py-2 pr-2">{untrusted ? <Untrusted why={f.note}>{val}</Untrusted> : val}<div className="text-[11px] text-muted">{f.note}</div></td>
              <td className="py-2 pr-2">
                <Pill tone={f.source_kind === "agent_asserted" ? "deny" : untrusted ? "untrusted" : "neutral"}>{SOURCE_LABEL[f.source_kind] ?? f.source_kind}</Pill>
              </td>
              <td className="py-2 pr-2"><Pill tone={f.consistency === "consistent" ? "allow" : f.consistency === "inconsistent" ? "deny" : "hold"}>{f.consistency}</Pill></td>
              <td className="py-2"><Pill tone={f.master_matched ? "allow" : "hold"}>{f.master_matched ? "matched" : "no match"}</Pill></td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function MasterDiff({ d }: { d: PaymentDetail }) {
  const verified = d.supplier?.accounts.filter((a) => a.status === "verified") ?? [];
  const same = verified.some((a) => a.id && a.id === d.proposed_account.id);
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <div className={cx("rounded-md border p-3", same ? "border-allow/40" : "border-deny/40 bg-deny-soft/40")}>
        <div className="text-[11.5px] font-medium text-muted">Proposed by the agent (from the invoice)</div>
        <div className="num mt-1 text-[15px]">{same ? d.proposed_account.masked : <Untrusted>{d.proposed_account.masked}</Untrusted>}</div>
        <div className="mt-1 text-[12px]"><Pill tone={d.proposed_account.status === "verified" ? "allow" : "deny"}>{d.proposed_account.status}</Pill></div>
        {d.proposed_account.cooling_off_until && <div className="mt-1 text-[11.5px] text-hold-ink">Cooling-off until {when(d.proposed_account.cooling_off_until)}</div>}
      </div>
      <div className="rounded-md border border-allow/40 p-3">
        <div className="text-[11.5px] font-medium text-muted">Verified in the supplier master</div>
        {verified.length === 0 && <div className="mt-1 text-[13px] text-muted">No verified account</div>}
        {verified.map((a) => (
          <div key={a.id} className="mt-1">
            <div className="num text-[15px]">{a.masked}</div>
            <div className="text-[11.5px] text-muted">{a.bank_name}. Verified by {a.verified_by ?? "?"} via {a.verified_method?.replace(/_/g, " ")}, approved by {a.steward_by ?? "?"}.</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AiPanel({ id }: { id: string }) {
  const { source } = useEnv();
  const [out, setOut] = useState<{ text: string; source: string; label: string } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Panel title={<span className="flex items-center gap-1.5"><Sparkles size={14} aria-hidden /> Explain this case</span>} actions={<Button isDisabled={busy} onPress={() => { setBusy(true); void source.explain(id).then(setOut).finally(() => setBusy(false)); }}>{busy ? "Thinking…" : out ? "Again" : "Explain"}</Button>}>
      {out ? (
        <div>
          <div className="mb-2 text-[11.5px] text-muted">{out.label} Source: <span className="num">{out.source}</span>.</div>
          {/* Model text is rendered as text, never as HTML. */}
          <p className="whitespace-pre-wrap text-[13px] leading-5 text-ink">{out.text}</p>
        </div>
      ) : (
        <p className="text-[12.5px] text-muted">The model sees reason codes and provenance facts only, never the email or invoice text, so injected instructions cannot steer it. It explains; it cannot decide.</p>
      )}
    </Panel>
  );
}

function Actions({ d }: { d: PaymentDetail }) {
  const { source, me, refresh, navigate } = useEnv();
  const roles = new Set(me?.roles ?? []);
  const clearable = d.reasons.filter((r) => CLEARABLE.has(r));
  const [code, setCode] = useState<string>(clearable[0] ?? "");
  const [note, setNote] = useState("Called the supplier on the number on file; confirmed.");
  const [msg, setMsg] = useState<{ tone: "allow" | "deny" | "hold"; text: string } | null>(null);
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try {
      await fn();
      setMsg({ tone: "allow", text: ok });
      refresh();
    } catch (e) {
      const err = e as ApiError;
      setMsg({ tone: "deny", text: `${err.code ?? "ERROR"}: ${err.message}` });
    }
  };
  const blocks: ReactNode[] = [];
  if (d.state === "held" && (roles.has("analyst") || roles.has("steward"))) {
    if (clearable.length) {
      blocks.push(
        <div key="clear" className="flex flex-col gap-2 rounded-md border border-line p-3">
          <div className="text-[12.5px] font-medium">Clear a signal hold after out of band review</div>
          <Select selectedKey={code} onSelectionChange={(k) => setCode(String(k))} className="flex flex-col gap-1">
            <Label className="text-[11.5px] text-muted">Hold to clear</Label>
            <AriaButton className="flex h-8 items-center justify-between rounded-md border border-line-strong px-2 text-[12.5px]"><SelectValue /></AriaButton>
            <Popover className="rounded-md border border-line bg-surface shadow-card"><ListBox className="p-1 text-[12.5px] outline-none">{clearable.map((c) => <ListBoxItem key={c} id={c} className="cursor-pointer rounded px-2 py-1 data-[focused]:bg-surface-2">{c}</ListBoxItem>)}</ListBox></Popover>
          </Select>
          <TextField value={note} onChange={setNote} className="flex flex-col gap-1"><Label className="text-[11.5px] text-muted">Note for the audit trail</Label><TextArea className="min-h-14 rounded-md border border-line-strong px-2 py-1 text-[12.5px]" /></TextField>
          <Button variant="primary" onPress={() => act(() => source.clearHold(d.id, code, note), `Cleared ${code}. You can no longer approve this payment (separation of duties).`)}>Clear hold and recheck</Button>
          <p className="text-[11.5px] text-muted">Beneficiary, supplier and field holds cannot be cleared by anyone. Only a verified master record clears them.</p>
        </div>,
      );
    }
    blocks.push(
      <div key="rd" className="flex gap-2">
        <Button onPress={() => act(() => source.recheck(d.id), "Rechecked against the current master and policy.")}><RefreshCw size={14} aria-hidden /> Recheck</Button>
        <Button variant="danger" onPress={() => act(() => source.deny(d.id, "Closed as fraud after review."), "Payment denied.")}>Deny</Button>
      </div>,
    );
  }
  if ((d.state === "awaiting_approval" || d.state === "approved") && roles.has("finance_approver")) {
    blocks.push(<Button key="appr" variant="primary" onPress={() => navigate(`/approvals?id=${d.id}`)}><Stamp size={14} aria-hidden /> Open in Approval Center</Button>);
  }
  if ((d.state === "awaiting_approval" || d.state === "approved") && roles.has("ap_specialist")) {
    blocks.push(
      <Button key="edit" onPress={() => act(() => source.edit(d.id, { amount_minor: d.amount_minor - 100 }), "Edited. Version bumped, every approval of the old version is void.")}>
        Correct amount by -1.00 (material change)
      </Button>,
    );
  }
  if (!blocks.length) return <p className="text-[12.5px] text-muted">No actions for your role in state “{STATE_LABEL[d.state]}”.</p>;
  return (
    <div className="flex flex-col gap-3">
      {msg && <Banner tone={msg.tone}>{msg.text}</Banner>}
      {blocks}
    </div>
  );
}

export function EvidenceInvestigation({ id }: { id: string | null }) {
  const { Link, policy } = useEnv();
  const { data: d, err } = useCase(id);
  const [focus, setFocus] = useState<string | null>(null);
  const transport = d?.email?.transport ?? {};
  const auth = (transport["auth"] ?? {}) as Record<string, string>;
  const signals = useMemo(() => d?.signals ?? [], [d]);
  if (!id) return <Empty title="No case selected" />;
  if (err) return <Banner tone="deny">{err}</Banner>;
  if (!d) return <div className="text-[13px] text-muted">Loading case…</div>;
  return (
    <div>
      <Link href="/" className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-ink-2 hover:text-ink"><ArrowLeft size={14} aria-hidden /> Payment Control</Link>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4 rounded-lg border border-line bg-surface p-4 shadow-card">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <StateBadge state={d.state} />
            <DecisionBadge decision={d.decision} />
            <span className="text-[12px] text-muted">version {d.version}</span>
          </div>
          <h1 className="mt-2 text-[20px] font-semibold tracking-tight">{d.supplier?.legal_name ?? "Unknown supplier"}</h1>
          <div className="mt-0.5 text-[12.5px] text-muted">Invoice {d.invoice_number ?? "without a number"}, proposed by <span className="num">{d.agent_id}</span> {when(d.created_at)}</div>
        </div>
        <div className="text-right">
          <Money minor={d.amount_minor} currency={d.currency} className="text-[24px] font-medium" />
          <div className="mt-1 text-[11.5px] text-muted">Canonical digest</div>
          <Digest value={d.digest} short />
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-4">
          <Panel title="Why" actions={<span className="text-[11.5px] text-muted">policy {policy?.sha256.slice(0, 8)}</span>}>
            {d.reason_details.length === 0 ? (
              <p className="text-[13px] text-allow">Every check passed. It still needs a passkey approval and a fresh policy run at execution.</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {d.reason_details.map((r) => (
                  <li key={r.code} className="flex items-start gap-2">
                    <ReasonChip code={r.code} cls={policy?.reason_codes[r.code]?.class} />
                    <span className="text-[12.5px] text-ink-2">{r.meaning}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Fields and where they came from">
            <FieldsTable d={d} setFocus={setFocus} />
            <p className="mt-2 text-[11.5px] text-muted"><span className="untrusted">Dotted violet</span> means untrusted origin with no match in a verified record. A span match proves extraction consistency, never authenticity.</p>
          </Panel>
          <Panel title="Beneficiary against the supplier master"><MasterDiff d={d} /></Panel>
          <Panel title="Lineage"><Lineage d={d} /></Panel>
          <Panel title="Actions"><Actions d={d} /></Panel>
          <AiPanel id={d.id} />
        </div>
        <div className="flex flex-col gap-4">
          <Panel title={<span className="flex items-center gap-1.5"><Mail size={14} aria-hidden /> Email transport</span>}>
            <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
              <dt className="text-muted">From</dt><dd className="num"><Untrusted>{String(transport["from"] ?? "")}</Untrusted></dd>
              <dt className="text-muted">Reply-To</dt><dd className="num">{String(transport["reply_to_domain"] ?? "same as sender")}</dd>
              <dt className="text-muted">Our server says</dt><dd className="num">spf={auth["spf"] ?? "?"} dkim={auth["dkim"] ?? "?"} dmarc={auth["dmarc"] ?? "?"}</dd>
              <dt className="text-muted">Subject</dt><dd>{String(transport["subject"] ?? "")}</dd>
            </dl>
            {signals.length > 0 && (
              <div className="mt-3 flex flex-col gap-1.5">
                {signals.map((s) => (
                  <div key={s.code} className="flex items-center gap-2 text-[12.5px]">
                    <ShieldAlert size={14} className="text-untrusted" aria-hidden />
                    <span className="font-medium">{humanize(s.code)}</span>
                    <Pill tone={s.severity === "high" ? "deny" : s.severity === "medium" ? "hold" : "neutral"}>{s.severity}</Pill>
                    <span className="truncate text-muted">{Object.entries(s.detail).filter(([k]) => k !== "excerpt").map(([k, v]) => `${k}: ${Array.isArray(v) ? v.length : String(v)}`).join(", ")}</span>
                  </div>
                ))}
                <p className="text-[11.5px] text-muted">Signals can only hold. They never allow.</p>
              </div>
            )}
          </Panel>
          <Panel title="Invoice, with each field linked to its source line"><InvoiceViewer d={d} focus={focus} /></Panel>
          <Panel title="Decisions and timeline">
            <ol className="relative flex flex-col gap-2 border-l border-line pl-4">
              {d.timeline.map((e) => (
                <li key={e.seq} className="text-[12px]">
                  <span className="absolute -left-[5px] mt-1 h-2.5 w-2.5 rounded-full border border-line-strong bg-surface" aria-hidden />
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-medium">{e.kind}</span>
                    <span className="text-muted">{e.actor}</span>
                    <span className="num text-muted">{when(e.at)}</span>
                    <span className="num text-[11px] text-muted" title="hash chain">#{e.seq} {e.hash}</span>
                  </div>
                  {Array.isArray(e.payload?.["reasons"]) && (e.payload?.["reasons"] as string[]).length > 0 && (
                    <div className="mt-0.5 flex flex-wrap gap-1">{(e.payload?.["reasons"] as string[]).map((r) => <ReasonChip key={r} code={r} />)}</div>
                  )}
                </li>
              ))}
            </ol>
          </Panel>
          {d.execution && (
            <Banner tone="allow" icon={<Bot size={14} aria-hidden />}>
              Executed on simulated rails. Bank reference <span className="num">{d.execution.bank_reference}</span>, {when(d.execution.executed_at)}.
            </Banner>
          )}
        </div>
      </div>
    </div>
  );
}
