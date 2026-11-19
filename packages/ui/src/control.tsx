"use client";

import {
  type ColumnDef,
  createSortedRowModel,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_basic,
  tableFeatures,
  useTable,
} from "@tanstack/react-table";
import { ArrowDownUp, Keyboard } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Dialog, DialogTrigger, Heading, Modal, ModalOverlay, TextArea, TextField, Label } from "react-aria-components";
import { ExposureByReason } from "./charts";
import { ago, compactMoney, money } from "./format";
import { Banner, Button, cx, Empty, Kbd, Money, Panel, ReasonChip, StateBadge, Stat } from "./primitives";
import { PageHeader, useEnv } from "./shell";
import type { QueueItem } from "./types";

const features = tableFeatures({
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
  sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
});

const FILTERS = [
  { id: "needs", label: "Needs me", test: (i: QueueItem) => i.state === "held" || i.state === "awaiting_approval" },
  { id: "held", label: "Held", test: (i: QueueItem) => i.state === "held" },
  { id: "approval", label: "Awaiting approval", test: (i: QueueItem) => i.state === "awaiting_approval" || i.state === "approved" },
  { id: "denied", label: "Denied", test: (i: QueueItem) => i.state === "denied" },
  { id: "done", label: "Executed", test: (i: QueueItem) => i.state === "executed" },
  { id: "all", label: "All", test: () => true },
] as const;
type FilterId = (typeof FILTERS)[number]["id"];

export function PaymentControl() {
  const { queue, policy, navigate, source, refresh, me } = useEnv();
  const [filter, setFilter] = useState<FilterId>(() => {
    try {
      return (localStorage.getItem("pl-filter") as FilterId | null) ?? "needs";
    } catch {
      return "needs";
    }
  });
  const [cursor, setCursor] = useState(0);
  const [denyFor, setDenyFor] = useState<QueueItem | null>(null);
  const tableRef = useRef<HTMLTableElement>(null);

  const chooseFilter = (f: FilterId) => {
    setFilter(f);
    setCursor(0);
    try {
      localStorage.setItem("pl-filter", f);
    } catch {
      /* ignore */
    }
  };
  const items = useMemo(() => (queue?.items ?? []).filter(FILTERS.find((f) => f.id === filter)?.test ?? (() => true)), [queue, filter]);

  const columns = useMemo<ColumnDef<typeof features, QueueItem>[]>(() => [
    { id: "state", accessorKey: "state", header: "Status", cell: (c) => <StateBadge state={c.row.original.state} />, sortFn: "alphanumeric" },
    {
      id: "supplier",
      accessorFn: (r) => r.supplier ?? "",
      header: "Supplier",
      cell: (c) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-ink">{c.row.original.supplier ?? <span className="text-muted">Unknown supplier</span>}</div>
          <div className="num truncate text-[11.5px] text-muted">{c.row.original.invoice_number ?? "no invoice number"}</div>
        </div>
      ),
      sortFn: "alphanumeric",
    },
    {
      id: "reasons",
      accessorFn: (r) => r.reasons.join(" "),
      header: "Why",
      enableSorting: false,
      cell: (c) => {
        const r = c.row.original.reasons;
        if (!r.length) return <span className="text-[12px] text-muted">All checks passed</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {r.slice(0, 3).map((code) => (
              <ReasonChip key={code} code={code} cls={policy?.reason_codes[code]?.class} meaning={policy?.reason_codes[code]?.meaning} />
            ))}
            {r.length > 3 && <span className="text-[12px] text-muted">+{r.length - 3}</span>}
          </div>
        );
      },
    },
    { id: "amount", accessorKey: "amount_minor", header: () => <span className="block text-right">Amount</span>, cell: (c) => <div className="text-right"><Money minor={c.row.original.amount_minor} currency={c.row.original.currency} /></div>, sortFn: "basic" },
    { id: "age", accessorFn: (r) => r.created_at ?? "", header: "Age", cell: (c) => <span className="num text-[12px] text-muted">{ago(c.row.original.created_at)}</span>, sortFn: "alphanumeric" },
  ], [policy]);

  const table = useTable({ features, columns, data: items, getRowId: (r) => r.id });
  const rows = table.getRowModel().rows;

  const open = useCallback((i: number) => {
    const r = rows[i];
    if (r) navigate(`/case?id=${r.original.id}`);
  }, [rows, navigate]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      if (denyFor) return;
      if (e.key === "j") setCursor((c) => Math.min(rows.length - 1, c + 1));
      else if (e.key === "k") setCursor((c) => Math.max(0, c - 1));
      else if (e.key === "Enter" && document.activeElement === document.body) open(cursor);
      else if (e.key === "h") chooseFilter("held");
      else if (e.key === "d") {
        const r = rows[cursor]?.original;
        if (r && r.state === "held") setDenyFor(r);
      } else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [rows, cursor, open, denyFor]);

  useEffect(() => {
    tableRef.current?.querySelector<HTMLElement>(`[data-row="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  if (!me) return null;
  const all = queue?.items ?? [];
  const held = all.filter((i) => i.state === "held");
  const awaiting = all.filter((i) => i.state === "awaiting_approval" || i.state === "approved");
  const denied = all.filter((i) => i.state === "denied");
  const exposure = held.reduce((s, i) => s + i.amount_minor, 0);
  const blocked = [...held, ...denied];
  const byReason = new Map<string, number>();
  for (const i of blocked) {
    const top = i.reasons.find((r) => policy?.reason_codes[r]?.class === "deny") ?? i.reasons[0];
    if (top) byReason.set(top, (byReason.get(top) ?? 0) + i.amount_minor);
  }
  const chartRows = [...byReason.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([code, minor]) => ({ code, minor, cls: policy?.reason_codes[code]?.class ?? "hold" }));

  return (
    <div>
      <PageHeader
        title="Payment Control"
        question="What needs me? Agent proposals, why each was held or denied, and what is exposed."
        actions={
          <span className="hidden items-center gap-1.5 text-[12px] text-muted md:flex">
            <Keyboard size={14} aria-hidden /> <Kbd>j</Kbd>/<Kbd>k</Kbd> move <Kbd>Enter</Kbd> open <Kbd>h</Kbd> holds <Kbd>d</Kbd> deny held
          </span>
        }
      />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Held for review" value={held.length} hint={`${compactMoney(exposure)} scenario exposure`} tone="hold" />
        <Stat label="Awaiting approval" value={awaiting.length} hint="passkey over the exact digest" />
        <Stat label="Denied by policy" value={denied.length} hint={`${compactMoney(denied.reduce((s, i) => s + i.amount_minor, 0))} refused`} tone="deny" />
        <Stat label="Executed (simulated)" value={all.filter((i) => i.state === "executed").length} hint="single use permits" tone="allow" />
      </div>
      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        <Panel
          dense
          title={
            <span className="flex items-center gap-1" role="tablist" aria-label="Saved filters">
              {FILTERS.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  role="tab"
                  aria-selected={filter === f.id}
                  onClick={() => chooseFilter(f.id)}
                  className={cx("rounded px-2 py-0.5 text-[12.5px]", filter === f.id ? "bg-ink text-paper" : "text-ink-2 hover:bg-surface-2")}
                >
                  {f.label}
                  <span className="num ml-1">{all.filter(f.test).length}</span>
                </button>
              ))}
            </span>
          }
        >
          {rows.length === 0 ? (
            <Empty title={filter === "needs" ? "Nothing needs you" : "No payments here"}>The agent's proposals land here after the policy evaluates them.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table ref={tableRef} className="w-full border-collapse text-[13px]" aria-label="Payment queue">
                <thead>
                  {table.getHeaderGroups().map((g) => (
                    <tr key={g.id} className="border-b border-line text-left text-[12px] text-muted">
                      {g.headers.map((h) => (
                        <th key={h.id} scope="col" className="px-3 py-2 font-medium" aria-sort={h.column.getIsSorted() === "asc" ? "ascending" : h.column.getIsSorted() === "desc" ? "descending" : "none"}>
                          {h.column.getCanSort() ? (
                            <button type="button" onClick={h.column.getToggleSortingHandler()} className="inline-flex items-center gap-1 hover:text-ink">
                              <table.FlexRender header={h} />
                              <ArrowDownUp size={11} aria-hidden />
                            </button>
                          ) : (
                            <table.FlexRender header={h} />
                          )}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {rows.map((row, i) => (
                    <tr
                      key={row.id}
                      data-row={i}
                      aria-selected={i === cursor}
                      onClick={() => {
                        setCursor(i);
                        open(i);
                      }}
                      className={cx("cursor-pointer border-b border-line last:border-0", i === cursor ? "bg-brand-soft/60" : "hover:bg-surface-2")}
                    >
                      {row.getAllCells().map((cell) => (
                        <td key={cell.id} className="px-3 py-2.5 align-middle">
                          {cell.column.id === "supplier" ? (
                            <a href={`/case?id=${row.original.id}`} onClick={(e) => e.preventDefault()} className="block outline-none" tabIndex={i === cursor ? 0 : -1} onKeyDown={(e) => e.key === "Enter" && open(i)}>
                              <table.FlexRender cell={cell} />
                            </a>
                          ) : (
                            <table.FlexRender cell={cell} />
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <div className="flex flex-col gap-4">
          <Panel title="Exposure held or denied, by reason">
            {chartRows.length ? <ExposureByReason rows={chartRows} label="Exposure by blocking reason" /> : <div className="text-[13px] text-muted">Nothing blocked.</div>}
            <p className="mt-2 text-[11.5px] text-muted">Scenario exposure, not savings. Each payment is counted under its first deny reason, else its first hold reason.</p>
          </Panel>
          <Panel title="How a decision is made">
            <ol className="list-decimal space-y-1 pl-4 text-[12.5px] text-ink-2">
              <li>Email and invoice values start untrusted.</li>
              <li>The beneficiary must match a verified master account.</li>
              <li>The agent's mandate bounds operation, supplier and amount.</li>
              <li>A person approves the exact digest with a passkey.</li>
              <li>The executor re-runs the policy and uses the permit once.</li>
            </ol>
          </Panel>
        </div>
      </div>
      <DenyDialog
        item={denyFor}
        onClose={() => setDenyFor(null)}
        onDeny={async (reason) => {
          if (!denyFor) return;
          await source.deny(denyFor.id, reason);
          setDenyFor(null);
          refresh();
        }}
      />
    </div>
  );
}

function DenyDialog({ item, onClose, onDeny }: { item: QueueItem | null; onClose: () => void; onDeny: (reason: string) => Promise<void> }) {
  const [reason, setReason] = useState("Confirmed fraud with the supplier on file.");
  const [err, setErr] = useState<string | null>(null);
  return (
    <DialogTrigger isOpen={item !== null} onOpenChange={(o) => !o && onClose()}>
      <span />
      <ModalOverlay className="fixed inset-0 z-40 grid place-items-center bg-ink/30 p-4">
        <Modal className="w-full max-w-md rounded-lg border border-line bg-surface p-5 shadow-card">
          <Dialog className="outline-none">
            <Heading slot="title" className="text-[15px] font-semibold">Close this held payment as denied?</Heading>
            {item && (
              <p className="mt-1 text-[13px] text-muted">
                {item.supplier ?? "Unknown supplier"}, <span className="num">{money(item.amount_minor, item.currency)}</span>. This is final.
              </p>
            )}
            <TextField className="mt-3 flex flex-col gap-1" value={reason} onChange={setReason}>
              <Label className="text-[12px] font-medium">Reason</Label>
              <TextArea className="min-h-20 rounded-md border border-line-strong bg-surface px-2 py-1.5 text-[13px]" />
            </TextField>
            {err && <div className="mt-2"><Banner tone="deny">{err}</Banner></div>}
            <div className="mt-4 flex justify-end gap-2">
              <Button onPress={onClose}>Cancel</Button>
              <Button variant="danger" onPress={() => onDeny(reason).catch((e: Error) => setErr(e.message))}>Deny payment</Button>
            </div>
          </Dialog>
        </Modal>
      </ModalOverlay>
    </DialogTrigger>
  );
}
