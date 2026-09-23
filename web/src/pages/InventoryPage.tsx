import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { HardDrive, Server } from "lucide-react";
import { AdminApi } from "../api";
import { usePrivacy } from "../privacy";
import { EmptyState } from "@/components/empty-state";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

function UtilizationBar({
  percent,
  label,
  compact = false,
}: {
  percent: number | null | undefined;
  label?: string;
  /** Table cells: percent + bar only (column header is the label). */
  compact?: boolean;
}) {
  const value =
    typeof percent === "number" && Number.isFinite(percent)
      ? Math.min(100, Math.max(0, percent))
      : null;
  const tone =
    value == null
      ? "bg-muted-foreground/25"
      : value >= 90
        ? "bg-destructive/80"
        : value >= 75
          ? "bg-amber-500/80"
          : "bg-foreground/65";

  if (compact) {
    return (
      <div className="w-[4.5rem] min-w-[4.5rem]">
        <div className="mb-0.5 font-mono text-[10px] tabular-nums text-muted-foreground">
          {value == null ? "—" : `${value.toFixed(0)}%`}
        </div>
        <div className="h-1 overflow-hidden rounded-sm bg-muted">
          <div
            className={`h-full transition-[width] ${tone}`}
            style={{ width: value == null ? "0%" : `${value}%` }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-w-[6rem]">
      <div className="mb-0.5 flex justify-between gap-2 text-[10px] text-muted-foreground">
        {label ? <span>{label}</span> : <span />}
        <span className="font-mono tabular-nums">
          {value == null ? "—" : `${value.toFixed(0)}%`}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-sm bg-muted">
        <div
          className={`h-full transition-[width] ${tone}`}
          style={{ width: value == null ? "0%" : `${value}%` }}
        />
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: unknown }) {
  const text = String(status ?? "unknown").toLowerCase();
  const running = text === "running" || text === "online";
  const stopped = text === "stopped" || text === "offline";
  return (
    <Badge
      variant="outline"
      className={
        running
          ? "border-emerald-600/40 text-emerald-700 dark:text-emerald-400"
          : stopped
            ? "border-muted-foreground/30 text-muted-foreground"
            : "border-amber-600/40 text-amber-700 dark:text-amber-400"
      }
    >
      {text}
    </Badge>
  );
}

function asNum(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

export function InventoryPage() {
  const { enabled: privacyOn } = usePrivacy();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [configured, setConfigured] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Array<Record<string, unknown>>>([]);
  const [vms, setVms] = useState<Array<Record<string, unknown>>>([]);
  const [lxc, setLxc] = useState<Array<Record<string, unknown>>>([]);
  const [storage, setStorage] = useState<Array<Record<string, unknown>>>([]);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<"name" | "cpu" | "mem" | "status">("name");
  const [selected, setSelected] = useState<{
    guest_type: string;
    guest_id: string;
    node?: string;
  } | null>(null);
  const [guestDetail, setGuestDetail] = useState<Record<string, unknown> | null>(null);
  const [guestLoading, setGuestLoading] = useState(false);

  useEffect(() => {
    void AdminApi.inventorySummary()
      .then((data) => {
        setConfigured(data.configured);
        setDetail(data.detail ?? null);
        setNodes(data.nodes ?? []);
        setVms(data.vms ?? []);
        setLxc(data.lxc ?? []);
        setStorage(data.storage ?? []);
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selected) {
      setGuestDetail(null);
      return;
    }
    setGuestLoading(true);
    void AdminApi.inventoryGuest(selected.guest_type, selected.guest_id, selected.node)
      .then((data) => setGuestDetail(data as Record<string, unknown>))
      .catch((err: Error) => setGuestDetail({ detail: err.message }))
      .finally(() => setGuestLoading(false));
  }, [selected]);

  function mask(value: unknown): string {
    const text = String(value ?? "—");
    if (!privacyOn) return text;
    if (text.length <= 4) return "••••";
    return `${text.slice(0, 2)}••••${text.slice(-2)}`;
  }

  const guests = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const rows = [...vms, ...lxc].filter((row) => {
      if (!q) return true;
      const hay = `${row.name ?? ""} ${row.vmid ?? ""} ${row.node ?? ""} ${row.status ?? ""}`.toLowerCase();
      return hay.includes(q);
    });
    rows.sort((a, b) => {
      if (sortKey === "cpu") {
        return (asNum(b.cpu_percent) ?? -1) - (asNum(a.cpu_percent) ?? -1);
      }
      if (sortKey === "mem") {
        return (asNum(b.mem_percent) ?? -1) - (asNum(a.mem_percent) ?? -1);
      }
      if (sortKey === "status") {
        return String(a.status ?? "").localeCompare(String(b.status ?? ""));
      }
      return String(a.name ?? a.vmid ?? "").localeCompare(String(b.name ?? b.vmid ?? ""));
    });
    return rows;
  }, [vms, lxc, filter, sortKey]);

  if (loading) return <LoadingBlock label="Loading inventory…" />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Inventory"
        description="Active-host utilization for nodes, guests, and storage (read-only)."
        actions={
          <Button asChild size="sm" variant="outline">
            <NavLink to="/tools">Open Tools</NavLink>
          </Button>
        }
      />

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {!configured ? (
        <EmptyState
          icon={Server}
          title="Inventory unavailable"
          description={detail ?? "Activate a host with secrets ready to browse cluster inventory."}
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="shadow-none">
            <CardHeader className="px-4 py-3">
              <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Nodes ({nodes.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="overflow-hidden px-0 pb-0">
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-8 w-[28%] px-3 text-[10px] uppercase">Name</TableHead>
                    <TableHead className="h-8 w-[16%] px-3 text-[10px] uppercase">Status</TableHead>
                    <TableHead className="h-8 w-[18%] px-3 text-[10px] uppercase">CPU</TableHead>
                    <TableHead className="h-8 w-[18%] px-3 text-[10px] uppercase">Mem</TableHead>
                    <TableHead className="h-8 w-[20%] px-3 text-[10px] uppercase">Uptime</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {nodes.map((node, idx) => (
                    <TableRow key={String(node.node ?? node.name ?? idx)}>
                      <TableCell className="truncate px-3 py-2 font-mono text-[11px]">
                        <div className="truncate">{mask(node.node ?? node.name)}</div>
                        {node.version ? (
                          <div className="truncate text-[10px] text-muted-foreground">
                            {String(node.version)}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <StatusBadge status={node.status} />
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <UtilizationBar percent={asNum(node.cpu_percent)} compact />
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <UtilizationBar percent={asNum(node.mem_percent)} compact />
                      </TableCell>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {formatUptime(asNum(node.uptime_seconds))}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card className="shadow-none">
            <CardHeader className="px-4 py-3">
              <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Storage ({storage.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="overflow-hidden px-0 pb-0">
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-8 w-[28%] px-3 text-[10px] uppercase">Storage</TableHead>
                    <TableHead className="h-8 w-[16%] px-3 text-[10px] uppercase">Node</TableHead>
                    <TableHead className="h-8 w-[20%] px-3 text-[10px] uppercase">Used</TableHead>
                    <TableHead className="h-8 w-[36%] px-3 text-[10px] uppercase">Content</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {storage.map((row, idx) => (
                    <TableRow key={`${String(row.storage ?? idx)}-${String(row.node)}`}>
                      <TableCell className="truncate px-3 py-2 font-mono text-[11px]">
                        {mask(row.storage)}
                      </TableCell>
                      <TableCell className="truncate px-3 py-2 font-mono text-[11px]">
                        {mask(row.node)}
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <UtilizationBar percent={asNum(row.used_percent)} compact />
                      </TableCell>
                      <TableCell className="truncate px-3 py-2 text-[10px] text-muted-foreground">
                        {Array.isArray(row.content_types)
                          ? row.content_types.join(", ") || "—"
                          : String(row.type ?? "—")}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card className="shadow-none lg:col-span-2">
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3 px-4 py-3">
              <CardTitle className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                <HardDrive className="size-3.5" />
                Guests — VMs ({vms.length}) / LXC ({lxc.length})
              </CardTitle>
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Filter guests…"
                  className="h-8 w-44 text-xs"
                />
                <select
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                  value={sortKey}
                  onChange={(e) => setSortKey(e.target.value as typeof sortKey)}
                >
                  <option value="name">Sort: name</option>
                  <option value="cpu">Sort: CPU</option>
                  <option value="mem">Sort: mem</option>
                  <option value="status">Sort: status</option>
                </select>
              </div>
            </CardHeader>
            <CardContent className="overflow-x-auto px-0 pb-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Type</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">ID</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Name</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Node</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Status</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">CPU</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Mem</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Disk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {guests.map((row, idx) => (
                    <TableRow
                      key={`${String(row.guest_type)}-${String(row.vmid ?? idx)}`}
                      className="cursor-pointer"
                      onClick={() =>
                        setSelected({
                          guest_type: String(row.guest_type ?? "vm"),
                          guest_id: String(row.vmid ?? ""),
                          node: row.node ? String(row.node) : undefined,
                        })
                      }
                    >
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {String(row.guest_type ?? "—")}
                      </TableCell>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {mask(row.vmid)}
                      </TableCell>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {mask(row.name)}
                      </TableCell>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {mask(row.node)}
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <StatusBadge status={row.status} />
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <UtilizationBar percent={asNum(row.cpu_percent)} compact />
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <UtilizationBar percent={asNum(row.mem_percent)} compact />
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <UtilizationBar percent={asNum(row.disk_percent)} compact />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}

      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="sm:max-w-md">
          <SheetHeader>
            <SheetTitle>Guest detail</SheetTitle>
            <SheetDescription>
              Read-only status and redacted config. Mutations stay on Tools + Approvals.
            </SheetDescription>
          </SheetHeader>
          {guestLoading ? (
            <LoadingBlock label="Loading guest…" />
          ) : guestDetail ? (
            <div className="mt-4 space-y-3 text-sm">
              {guestDetail.detail ? (
                <p className="text-destructive">{String(guestDetail.detail)}</p>
              ) : (
                <>
                  <dl className="grid grid-cols-[7rem_1fr] gap-x-2 gap-y-1 font-mono text-[11px]">
                    <dt className="text-muted-foreground">Type</dt>
                    <dd>{String(guestDetail.guest_type ?? "—")}</dd>
                    <dt className="text-muted-foreground">ID</dt>
                    <dd>{mask(guestDetail.guest_id)}</dd>
                    <dt className="text-muted-foreground">Node</dt>
                    <dd>{mask(guestDetail.node)}</dd>
                    <dt className="text-muted-foreground">Status</dt>
                    <dd>
                      <StatusBadge
                        status={
                          (guestDetail.guest as Record<string, unknown> | undefined)?.status
                        }
                      />
                    </dd>
                  </dl>
                  <UtilizationBar
                    percent={asNum(
                      (guestDetail.guest as Record<string, unknown> | undefined)?.cpu_percent,
                    )}
                    label="CPU"
                  />
                  <UtilizationBar
                    percent={asNum(
                      (guestDetail.guest as Record<string, unknown> | undefined)?.mem_percent,
                    )}
                    label="Mem"
                  />
                  <div className="flex gap-2 pt-2">
                    <Button asChild size="sm" variant="outline">
                      <NavLink
                        to={`/tools?target=${encodeURIComponent(String(guestDetail.guest_id ?? ""))}`}
                      >
                        Open in Tools
                      </NavLink>
                    </Button>
                  </div>
                  <details className="rounded-md border p-2">
                    <summary className="cursor-pointer text-xs font-medium">Config summary</summary>
                    <pre className="mt-2 max-h-64 overflow-auto text-[10px]">
                      {JSON.stringify(guestDetail.config_summary ?? {}, null, 2)}
                    </pre>
                  </details>
                </>
              )}
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function formatUptime(seconds: number | null): string {
  if (seconds == null || seconds < 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h`;
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export { StatusBadge, UtilizationBar };
