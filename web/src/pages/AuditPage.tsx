import { useCallback, useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { Activity, Copy, X } from "lucide-react";
import { AdminApi, type AuditEvent } from "../api";
import { useAdminEvents } from "../useEvents";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { useMediaQuery } from "../hooks/useMediaQuery";
import { formatLocal, relativeTime } from "../lib/format";
import { EmptyState } from "@/components/empty-state";
import { KvPanel } from "@/components/kv-panel";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

const STATUS_FILTERS = ["all", "success", "error", "denied", "started"] as const;

const DENIAL_EXPLAIN: Record<string, string> = {
  TOOL_NOT_GRANTED: "Capability ACL did not grant this tool to the actor (deny-by-default).",
  RBAC_DENIED: "Actor lacks the required permission pack for this operation.",
  POLICY_DENIED: "Policy engine denied the request.",
  DANGEROUS_OPERATION_DISABLED: "Dangerous operations are disabled in runtime policy.",
  RATE_LIMITED: "Caller exceeded rate limits.",
  APPROVAL_REQUIRED: "A pending approval token is required before execution.",
  APPROVAL_SCOPE_MISMATCH: "Approval token does not match this operation or target.",
  AUTHENTICATION_REQUIRED: "No authenticated session/token was presented.",
  AUTHENTICATION_FAILED: "Credentials were rejected.",
};

function metaOf(event: AuditEvent): Record<string, unknown> {
  return (event.metadata ?? {}) as Record<string, unknown>;
}

function diagnosisLine(event: AuditEvent): string {
  const meta = metaOf(event);
  const reason = String(meta.denial_reason ?? event.error_code ?? "");
  if (reason && DENIAL_EXPLAIN[reason]) return DENIAL_EXPLAIN[reason];
  if (event.result_status === "denied") {
    return reason ? `Denied: ${reason}` : "Request denied by the security plane.";
  }
  if (event.result_status === "error") {
    return event.error_code
      ? `Execution failed with ${event.error_code}.`
      : "Execution failed — inspect error panel and metadata.";
  }
  if (event.result_status === "success") return "Completed successfully.";
  return `Status: ${event.result_status}`;
}

function shareableSummary(event: AuditEvent): string {
  const meta = metaOf(event);
  return [
    `event_id=${event.event_id}`,
    `tool=${event.tool_name}`,
    `status=${event.result_status}`,
    `error=${event.error_code ?? "-"}`,
    `denial=${String(meta.denial_reason ?? "-")}`,
    `actor=${event.actor_user_id}/${event.actor_agent_id}`,
    `when=${event.timestamp}`,
  ].join(" ");
}

function Timeline({ event }: { event: AuditEvent }) {
  const meta = metaOf(event);
  const steps = [
    { label: "Started", value: formatLocal(event.timestamp) },
    {
      label: "Decided",
      value:
        meta.decision_at != null
          ? String(meta.decision_at)
          : event.result_status === "denied" || event.result_status === "error"
            ? "at finish"
            : "allowed",
    },
    {
      label: "Finished",
      value:
        meta.duration_ms != null
          ? `${meta.duration_ms} ms`
          : event.duration_ms != null
            ? `${event.duration_ms} ms`
            : "—",
    },
  ];
  return (
    <ol className="grid gap-2 sm:grid-cols-3">
      {steps.map((step) => (
        <li key={step.label} className="rounded-md border border-border/70 px-3 py-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            {step.label}
          </div>
          <div className="mt-1 font-mono text-[11px]">{step.value}</div>
        </li>
      ))}
    </ol>
  );
}

function EventDetail({
  selected,
  onClose,
}: {
  selected: AuditEvent;
  onClose?: () => void;
}) {
  const meta = metaOf(selected);
  const isBad =
    selected.result_status === "denied" ||
    selected.result_status === "error" ||
    Boolean(selected.error_code);
  const denial = String(meta.denial_reason ?? selected.error_code ?? "");

  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="space-y-4">
      <div
        className={cn(
          "rounded-md border px-3 py-3",
          isBad ? "border-destructive/40 bg-destructive/10" : "border-border bg-muted/20",
        )}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={selected.result_status} />
              {denial ? (
                <Badge variant="outline" className="font-mono text-[10px]">
                  {denial}
                </Badge>
              ) : null}
              <span className="rounded-sm bg-muted/40 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                {selected.operation}
              </span>
            </div>
            <h2 className="truncate font-mono text-[14px] font-semibold">{selected.tool_name}</h2>
            <p className="text-[12px] leading-snug text-muted-foreground">{diagnosisLine(selected)}</p>
            <p className="truncate font-mono text-[11px] text-muted-foreground" title={selected.event_id}>
              {selected.event_id}
            </p>
          </div>
          <div className="flex shrink-0 gap-1">
            <Button
              type="button"
              size="xs"
              variant="ghost"
              onClick={() => void copyText(selected.event_id)}
              aria-label="Copy event id"
            >
              <Copy className="size-3.5" />
            </Button>
            {onClose ? (
              <Button type="button" size="xs" variant="ghost" onClick={onClose} aria-label="Close">
                <X className="size-3.5" />
              </Button>
            ) : null}
          </div>
        </div>
        <div className="mt-3">
          <Button
            type="button"
            size="xs"
            variant="outline"
            onClick={() => void copyText(shareableSummary(selected))}
          >
            Copy shareable summary
          </Button>
        </div>
      </div>

      <div>
        <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Timeline
        </div>
        <Timeline event={selected} />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border px-3 py-2.5">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Actor / Auth
          </div>
          <dl className="mt-2 space-y-1 font-mono text-[11px]">
            <div className="flex justify-between gap-2">
              <dt className="text-muted-foreground">User</dt>
              <dd className="truncate">{selected.actor_user_id}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-muted-foreground">Agent</dt>
              <dd className="truncate">{selected.actor_agent_id}</dd>
            </div>
            {meta.auth_method != null ? (
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Auth</dt>
                <dd>{String(meta.auth_method)}</dd>
              </div>
            ) : null}
          </dl>
        </div>
        <div className="rounded-md border border-border px-3 py-2.5">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Decision
          </div>
          <dl className="mt-2 space-y-1 font-mono text-[11px]">
            <div className="flex justify-between gap-2">
              <dt className="text-muted-foreground">Outcome</dt>
              <dd>{selected.result_status}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-muted-foreground">Risk</dt>
              <dd>{String(meta.risk_level ?? meta.risk ?? "—")}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-muted-foreground">Rule</dt>
              <dd className="truncate">{String(meta.matched_rule ?? selected.tool_name)}</dd>
            </div>
            {meta.approval_request_id != null ? (
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Approval</dt>
                <dd className="truncate">{String(meta.approval_request_id)}</dd>
              </div>
            ) : null}
          </dl>
        </div>
      </div>

      {isBad ? (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2.5 text-xs">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-destructive opacity-80">
            Error / denial
          </div>
          <div className="mt-1 font-mono text-destructive">
            {(selected.error_code ?? denial) || "denied"}
          </div>
          <p className="mt-2 text-[12px] text-muted-foreground">{diagnosisLine(selected)}</p>
          {meta.http_status != null ? (
            <p className="mt-1 font-mono text-[11px]">HTTP {String(meta.http_status)}</p>
          ) : null}
        </div>
      ) : null}

      <KvPanel title="Target" data={(selected.target ?? {}) as Record<string, unknown>} />

      <details className="rounded-md border border-border">
        <summary className="cursor-pointer px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Redacted metadata (JSON)
        </summary>
        <pre className="max-h-64 overflow-auto border-t border-border/70 px-3 py-2 font-mono text-[10px]">
          {JSON.stringify(meta, null, 2)}
        </pre>
      </details>

      {typeof meta.proxmox_task_upid === "string" ? (
        <Button asChild size="sm" variant="outline">
          <NavLink to={`/tasks?upid=${encodeURIComponent(String(meta.proxmox_task_upid))}`}>
            Open UPID in Tasks
          </NavLink>
        </Button>
      ) : null}
    </div>
  );
}

export function AuditPage() {
  const split = useMediaQuery("(min-width: 1280px)");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [toolFilter, setToolFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const debouncedFilter = useDebouncedValue(toolFilter, 300);

  const prepend = useCallback(
    (event: AuditEvent) => {
      setEvents((prev) => {
        if (prev.some((e) => e.event_id === event.event_id)) return prev;
        if (debouncedFilter.trim() && !event.tool_name.includes(debouncedFilter.trim())) {
          return prev;
        }
        return [event, ...prev].slice(0, 200);
      });
    },
    [debouncedFilter],
  );

  const { connection } = useAdminEvents(prepend);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "75" });
    if (debouncedFilter.trim()) params.set("tool_name", debouncedFilter.trim());
    void AdminApi.audit(params)
      .then((res) => setEvents(res.events))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [debouncedFilter]);

  const visible = useMemo(() => {
    if (statusFilter === "all") return events;
    return events.filter((e) => e.result_status.toLowerCase() === statusFilter);
  }, [events, statusFilter]);

  useEffect(() => {
    if (selected && !visible.some((e) => e.event_id === selected.event_id)) {
      setSelected(null);
    }
  }, [visible, selected]);

  const list = (
    <div className="min-w-0 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-[12rem] flex-1">
          <Label htmlFor="audit-tool" className="sr-only">
            Tool filter
          </Label>
          <Input
            id="audit-tool"
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            placeholder="Filter by tool…"
            className="h-8"
          />
        </div>
        <div className="flex flex-wrap gap-1">
          {STATUS_FILTERS.map((status) => (
            <Button
              key={status}
              type="button"
              size="xs"
              variant={statusFilter === status ? "default" : "outline"}
              onClick={() => setStatusFilter(status)}
            >
              {status}
            </Button>
          ))}
        </div>
        <Badge variant="outline" className="font-mono text-[10px]">
          sse:{connection}
        </Badge>
      </div>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {loading ? <LoadingBlock label="Loading audit…" /> : null}

      {!loading && visible.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No audit events"
          description="Invocations and denials will appear here."
        />
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-8 px-3 text-[10px] uppercase">When</TableHead>
                <TableHead className="h-8 px-3 text-[10px] uppercase">Tool</TableHead>
                <TableHead className="h-8 px-3 text-[10px] uppercase">Status</TableHead>
                <TableHead className="h-8 px-3 text-[10px] uppercase">Code</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((event) => (
                <TableRow
                  key={event.event_id}
                  className={cn(
                    "cursor-pointer",
                    selected?.event_id === event.event_id && "bg-muted/40",
                  )}
                  onClick={() => setSelected(event)}
                >
                  <TableCell className="px-3 py-2 font-mono text-[11px]" title={formatLocal(event.timestamp)}>
                    {relativeTime(event.timestamp)}
                  </TableCell>
                  <TableCell className="px-3 py-2 font-mono text-[11px]">{event.tool_name}</TableCell>
                  <TableCell className="px-3 py-2">
                    <StatusBadge status={event.result_status} />
                  </TableCell>
                  <TableCell className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                    {event.error_code ??
                      String((event.metadata as Record<string, unknown> | undefined)?.denial_reason ?? "—")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="Audit"
        description="Troubleshoot allows, denials, and errors with structured metadata."
      />
      {split ? (
        <div className="grid gap-4 xl:grid-cols-[1fr_24rem]">
          {list}
          <div className="min-h-[20rem] rounded-md border border-border p-4">
            {selected ? (
              <EventDetail selected={selected} onClose={() => setSelected(null)} />
            ) : (
              <p className="text-sm text-muted-foreground">Select an event to inspect.</p>
            )}
          </div>
        </div>
      ) : (
        <>
          {list}
          <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
            <SheetContent className="overflow-y-auto sm:max-w-md">
              <SheetHeader>
                <SheetTitle>Audit event</SheetTitle>
                <SheetDescription>Structured denial and error detail for triage.</SheetDescription>
              </SheetHeader>
              {selected ? <div className="mt-4"><EventDetail selected={selected} /></div> : null}
            </SheetContent>
          </Sheet>
        </>
      )}
    </div>
  );
}

export { diagnosisLine, shareableSummary };
