import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, X } from "lucide-react";
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

function summaryFields(event: AuditEvent): Array<{ label: string; value: string }> {
  const meta = (event.metadata ?? {}) as Record<string, unknown>;
  const rows: Array<{ label: string; value: string }> = [
    { label: "Time", value: formatLocal(event.timestamp) },
    { label: "Actor", value: `${event.actor_user_id} · ${event.actor_agent_id}` },
  ];
  if (event.duration_ms != null) {
    rows.push({ label: "Duration", value: `${event.duration_ms} ms` });
  }
  if (meta.connector != null) {
    rows.push({ label: "Connector", value: String(meta.connector) });
  }
  if (meta.risk != null) {
    rows.push({ label: "Risk", value: String(meta.risk) });
  }
  if (meta.request_id != null) {
    rows.push({ label: "Request", value: String(meta.request_id) });
  }
  return rows;
}

function EventDetail({
  selected,
  onClose,
}: {
  selected: AuditEvent;
  onClose?: () => void;
}) {
  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-2 border-b border-border/70 pb-3">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={selected.result_status} />
            <span className="rounded-sm bg-muted/40 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
              {selected.operation}
            </span>
          </div>
          <h2 className="truncate font-mono text-[14px] font-semibold">{selected.tool_name}</h2>
          <p className="truncate font-mono text-[11px] text-muted-foreground" title={selected.event_id}>
            {selected.event_id}
          </p>
        </div>
        {onClose ? (
          <Button type="button" size="xs" variant="ghost" onClick={onClose} aria-label="Close">
            <X className="size-3.5" />
          </Button>
        ) : null}
      </div>

      {selected.error_code ? (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2.5 text-xs text-destructive">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] opacity-80">
            Error
          </div>
          <div className="mt-0.5 font-mono">{selected.error_code}</div>
        </div>
      ) : null}

      <div className="overflow-hidden rounded-md border border-border">
        <div className="border-b border-border/70 bg-muted/20 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Summary
        </div>
        <div>
          {summaryFields(selected).map((row) => (
            <div
              key={row.label}
              className="grid grid-cols-[92px_1fr] items-start gap-3 border-b border-border/50 px-3 py-2.5 last:border-0"
            >
              <div className="pt-0.5 text-[11px] text-muted-foreground">{row.label}</div>
              <div className="min-w-0 break-all font-mono text-[12px] leading-snug">{row.value}</div>
            </div>
          ))}
        </div>
      </div>

      <KvPanel title="Target" data={(selected.target ?? {}) as Record<string, unknown>} />
      <KvPanel title="Metadata" data={(selected.metadata ?? {}) as Record<string, unknown>} />
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
        <div className="flex flex-wrap gap-1">
          {STATUS_FILTERS.map((s) => (
            <Button
              key={s}
              type="button"
              size="xs"
              variant={statusFilter === s ? "default" : "outline"}
              className={cn(
                "h-7 px-2 font-mono text-[10px] uppercase",
                statusFilter === s && "bg-primary text-primary-foreground",
              )}
              onClick={() => setStatusFilter(s)}
            >
              {s}
            </Button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <Label
            htmlFor="tool-filter"
            className="whitespace-nowrap text-[10px] uppercase tracking-wide text-muted-foreground"
          >
            Tool
          </Label>
          <Input
            id="tool-filter"
            className="h-7 w-[160px] font-mono text-xs"
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            placeholder="list_nodes"
          />
        </div>
      </div>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {loading && events.length === 0 ? (
        <LoadingBlock label="Loading audit events…" />
      ) : visible.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No events"
          description="Adjust filters or wait for agent/admin traffic — live events stream automatically."
        />
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Time
                </TableHead>
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Tool
                </TableHead>
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Status
                </TableHead>
                <TableHead className="h-8 px-3 text-right text-[10px] font-semibold uppercase tracking-[0.12em]">
                  ms
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((event) => (
                <TableRow
                  key={event.event_id}
                  className={cn(
                    "cursor-pointer",
                    selected?.event_id === event.event_id && "bg-primary/10",
                  )}
                  onClick={() => setSelected(event)}
                >
                  <TableCell className="px-3 py-1.5" title={formatLocal(event.timestamp)}>
                    <div className="font-mono text-[11px]">{relativeTime(event.timestamp)}</div>
                  </TableCell>
                  <TableCell className="px-3 py-1.5">
                    <div className="font-mono text-[11px]">{event.tool_name}</div>
                    <div className="text-[10px] text-muted-foreground">{event.actor_user_id}</div>
                  </TableCell>
                  <TableCell className="px-3 py-1.5">
                    <StatusBadge status={event.result_status} />
                  </TableCell>
                  <TableCell className="px-3 py-1.5 text-right font-mono text-[11px] text-muted-foreground">
                    {event.duration_ms ?? "—"}
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
    <div className="space-y-3">
      <PageHeader
        title="Audit"
        description="Live stream of MCP and admin actions."
        actions={
          <Badge
            variant="outline"
            className={cn(
              "h-7 gap-1.5 border-primary/35 px-2 text-[10px] font-medium uppercase tracking-wide",
              connection === "live"
                ? "bg-primary/10 text-primary"
                : "border-muted-foreground/30 bg-muted/30 text-muted-foreground",
            )}
          >
            <span
              className={cn(
                "size-1.5 rounded-full",
                connection === "live"
                  ? "animate-pulse bg-primary"
                  : connection === "reconnecting"
                    ? "animate-pulse bg-[oklch(0.82_0.14_70)]"
                    : "bg-muted-foreground",
              )}
            />
            {connection === "live"
              ? "Live"
              : connection === "reconnecting"
                ? "Reconnecting"
                : connection === "connecting"
                  ? "Connecting"
                  : "Offline"}
          </Badge>
        }
      />

      {split ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
          {list}
          <div className="min-h-[420px] rounded-md border border-border bg-card/30 p-4">
            {selected ? (
              <EventDetail selected={selected} onClose={() => setSelected(null)} />
            ) : (
              <EmptyState
                icon={Activity}
                title="Select an event"
                description="Click a row to inspect target, metadata, and timing."
                className="border-0 bg-transparent py-16"
              />
            )}
          </div>
        </div>
      ) : (
        <>
          {list}
          <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
            <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
              {selected ? (
                <>
                  <SheetHeader className="sr-only">
                    <SheetTitle>{selected.tool_name}</SheetTitle>
                    <SheetDescription>Audit event detail</SheetDescription>
                  </SheetHeader>
                  <div className="mt-2 px-1">
                    <EventDetail selected={selected} />
                  </div>
                </>
              ) : null}
            </SheetContent>
          </Sheet>
        </>
      )}
    </div>
  );
}
