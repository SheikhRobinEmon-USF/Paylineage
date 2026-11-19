"use client";

import { CheckCircle2, CircleAlert, Fingerprint, KeyRound, Send } from "lucide-react";
import { useEffect, useState } from "react";
import { when } from "./format";
import { Banner, Button, Digest, Empty, Money, Panel, Pill, ReasonChip, StateBadge, cx } from "./primitives";
import { PageHeader, useEnv } from "./shell";
import { ApiError, type ApprovalResult, type ApprovalStart, type PaymentDetail } from "./types";

type Step = "review" | "signing" | "approved" | "permitted" | "executed" | "refused";

const EXPLAIN: Record<string, string> = {
  APPROVAL_EXPIRED: "The approval expired before the permit was issued. Approve again.",
  MANDATE_REVOKED: "The agent's mandate was revoked after approval. A valid signature cannot bring it back.",
  APPROVAL_DIGEST_MISMATCH: "The record changed after you saw it. Review the new version.",
  SOD_VIOLATION: "You touched this supplier's bank details or cleared its holds. Someone else must approve.",
  APPROVER_NOT_AUTHORIZED: "Your approval permission is missing or was revoked.",
  SECOND_APPROVAL_REQUIRED: "Your approval is recorded. This amount needs a second, different approver.",
};

export function ApprovalCenter({ id }: { id: string | null }) {
  const { queue, navigate, me } = useEnv();
  const waiting = (queue?.items ?? []).filter((i) => i.state === "awaiting_approval" || i.state === "approved" || i.state === "permit_issued");
  const canApprove = me?.roles.includes("finance_approver") ?? false;
  return (
    <div>
      <PageHeader title="Approval Center" question="Am I approving exactly this? One payment at a time, bound to its digest." />
      {!canApprove && <div className="mb-3"><Banner tone="hold">Your role cannot approve payments. Sign in as a finance approver to approve.</Banner></div>}
      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <Panel title="Ready for approval" dense>
          {waiting.length === 0 ? (
            <Empty title="Nothing to approve" />
          ) : (
            <ul className="divide-y divide-line">
              {waiting.map((i) => (
                <li key={i.id}>
                  <button type="button" onClick={() => navigate(`/approvals?id=${i.id}`)} className={cx("w-full px-3 py-2.5 text-left hover:bg-surface-2", id === i.id && "bg-brand-soft/60")} aria-current={id === i.id ? "true" : undefined}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-[13px] font-medium">{i.supplier}</span>
                      <Money minor={i.amount_minor} currency={i.currency} className="text-[12.5px]" />
                    </div>
                    <div className="mt-1"><StateBadge state={i.state} /></div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        {id ? <ApproveOne key={id} id={id} canApprove={canApprove} /> : <Panel><Empty title="Choose a payment">You will see the full canonical record and its digest before you sign.</Empty></Panel>}
      </div>
    </div>
  );
}

function ApproveOne({ id, canApprove }: { id: string; canApprove: boolean }) {
  const { source, refresh, version } = useEnv();
  const [detail, setDetail] = useState<PaymentDetail | null>(null);
  const [start, setStart] = useState<ApprovalStart | null>(null);
  const [step, setStep] = useState<Step>("review");
  const [result, setResult] = useState<ApprovalResult | null>(null);
  const [error, setError] = useState<{ code: string; message: string; reasons?: string[] } | null>(null);
  const [log, setLog] = useState<string[]>([]);
  useEffect(() => {
    void source.payment(id).then(setDetail);
  }, [id, source, version]);

  const fail = (e: unknown) => {
    const err = e as ApiError;
    const detailObj = (err.detail ?? {}) as { reasons?: string[]; detail?: { reasons?: string[] } };
    const reasons = detailObj.reasons ?? detailObj.detail?.reasons;
    setError({ code: err.code ?? "ERROR", message: err.message, ...(reasons ? { reasons } : {}) });
    setStep("refused");
    refresh();
  };

  const approve = async () => {
    setError(null);
    try {
      const s = await source.beginApproval(id);
      setStart(s);
      setStep("signing");
      const cred = await source.passkey(s.options);
      const r = await source.finishApproval(id, s.challenge_id, cred);
      setResult(r);
      setLog((l) => [...l, `Approval recorded for digest ${r.receipt?.digest.slice(0, 12)}…`]);
      setStep(r.state === "approved" ? "approved" : "review");
      refresh();
    } catch (e) {
      fail(e);
    }
  };
  const permit = async () => {
    try {
      const r = await source.permit(id);
      setLog((l) => [...l, `Fresh policy run at permit: ${r.decision}. Permit ${String(r["permit_id"]).slice(0, 8)}… valid 2 minutes, single use.`]);
      setStep("permitted");
      refresh();
    } catch (e) {
      fail(e);
    }
  };
  const execute = async () => {
    try {
      const r = await source.execute(id);
      const ok = r["executed"] === true;
      setLog((l) => [...l, ok ? `Executor revalidated, consumed the permit and paid. Reference ${String(r["bank_reference"])} (simulated).` : `Executor refused: ${JSON.stringify((r["decision"] as { reasons?: string[] } | undefined)?.reasons)}`]);
      setStep(ok ? "executed" : "refused");
      refresh();
    } catch (e) {
      fail(e);
    }
  };

  if (!detail) return <Panel><div className="text-[13px] text-muted">Loading…</div></Panel>;
  const record = start?.record ?? detail.record;
  const digest = start?.digest ?? detail.digest;
  const verifiedMatch = detail.fields.find((f) => f.field_name === "beneficiary_account")?.master_matched;
  return (
    <div className="flex flex-col gap-4">
      <Panel title="You are approving exactly this record" actions={<StateBadge state={detail.state} />}>
        <div className="grid gap-4 md:grid-cols-[1fr_1fr]">
          <ul className="flex flex-col gap-2 text-[13px]">
            <Check ok label={<>Pay <Money minor={detail.amount_minor} currency={detail.currency} /> to {detail.supplier?.legal_name}</>} />
            <Check ok={verifiedMatch ?? false} label={<>Beneficiary <span className="num">{detail.proposed_account.masked}</span> {verifiedMatch ? "matches the verified master account" : "is NOT a verified master account"}</>} />
            <Check ok={detail.reasons.length === 0} label={detail.reasons.length === 0 ? "No holds: every material field traces to a trusted record" : <span className="flex flex-wrap gap-1">Open reasons {detail.reasons.map((r) => <ReasonChip key={r} code={r} />)}</span>} />
            <Check ok label={<>Record version {detail.version}, policy <span className="num">{detail.policy_sha256.slice(0, 10)}…</span></>} />
          </ul>
          <div>
            <div className="text-[11.5px] font-medium text-muted">SHA-256 over the RFC 8785 canonical record</div>
            <div className="mt-1 rounded-md border border-line bg-surface-2 p-2"><Digest value={digest} /></div>
            <p className="mt-2 text-[11.5px] text-muted">Your passkey signs a server challenge that commits to this digest. Any change to amount, beneficiary, supplier, invoice, mandate or policy voids it, even with a valid signature. The screen itself is not a trusted display.</p>
          </div>
        </div>
        <details className="mt-3">
          <summary className="cursor-pointer text-[12.5px] text-ink-2">Canonical record (every field that is hashed)</summary>
          <table className="mt-2 w-full text-[12px]">
            <tbody>
              {Object.entries(record).map(([k, v]) => (
                <tr key={k} className="border-b border-line last:border-0">
                  <th scope="row" className="w-48 py-1 pr-3 text-left font-normal text-muted">{k}</th>
                  <td className="num break-all py-1">{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </Panel>

      <Panel title="Approve, permit, execute">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" isDisabled={!canApprove || detail.state !== "awaiting_approval" || step === "signing"} onPress={approve}>
            <Fingerprint size={15} aria-hidden /> {step === "signing" ? "Waiting for passkey…" : source.mode === "demo" ? "Approve with simulated passkey" : "Approve with passkey"}
          </Button>
          <Button isDisabled={detail.state !== "approved"} onPress={permit}><KeyRound size={15} aria-hidden /> Issue permit</Button>
          <Button isDisabled={detail.state !== "permit_issued"} onPress={execute}><Send size={15} aria-hidden /> Execute (simulated rails)</Button>
        </div>
        {result?.receipt && (
          <div className="mt-3 rounded-md border border-allow/40 bg-allow-soft/50 p-3 text-[12.5px]">
            <div className="font-medium text-allow">Decision receipt</div>
            <div>Approval <span className="num">{result.receipt.approval_id.slice(0, 8)}</span> for version {result.receipt.version}, signed {when(result.receipt.signed_at)}, expires {when(result.receipt.expires_at)}.</div>
            <div className="mt-1"><Digest value={result.receipt.digest} short /></div>
            {result.reasons.includes("SECOND_APPROVAL_REQUIRED") && <div className="mt-1 text-hold-ink">{EXPLAIN["SECOND_APPROVAL_REQUIRED"]}</div>}
          </div>
        )}
        {error && (
          <div className="mt-3">
            <Banner tone="deny" icon={<CircleAlert size={15} aria-hidden />}>
              <div className="font-medium">{error.code}</div>
              <div>{EXPLAIN[error.code] ?? error.message}</div>
              {error.reasons && <div className="mt-1 flex flex-wrap gap-1">{error.reasons.map((r) => <ReasonChip key={r} code={r} />)}</div>}
            </Banner>
          </div>
        )}
        {log.length > 0 && (
          <ol className="mt-3 list-decimal pl-5 text-[12.5px] text-ink-2">
            {log.map((l, i) => <li key={i}>{l}</li>)}
          </ol>
        )}
        {detail.approvals.length > 0 && (
          <div className="mt-3 text-[12px] text-muted">
            Approvals on file: {detail.approvals.map((a) => <Pill key={a.id} className="ml-1">{a.approver} v{a.version}{a.revoked_at ? " revoked" : ""}</Pill>)}
          </div>
        )}
      </Panel>
    </div>
  );
}

function Check({ ok, label }: { ok: boolean; label: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2">
      {ok ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-allow" aria-label="yes" /> : <CircleAlert size={16} className="mt-0.5 shrink-0 text-deny" aria-label="no" />}
      <span>{label}</span>
    </li>
  );
}
