import { useEffect, useState } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { ListTodo, RefreshCw } from "lucide-react";
import { AdminApi, type TaskRow } from "../api";
import { formatLocal, relativeTime } from "../lib/format";
import { EmptyState } from "@/components/empty-state";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function TasksPage() {
  const [searchParams] = useSearchParams();
  const focusUpid = searchParams.get("upid");
  const [rows, setRows] = useState<TaskRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyUpid, setBusyUpid] = useState<string | null>(null);

  async function refresh() {
    const data = await AdminApi.tasks();
    setRows(data.tasks);
  }

  useEffect(() => {
    void refresh()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function onRefresh(upid: string) {
    setBusyUpid(upid);
    setError(null);
    try {
      await AdminApi.refreshTask(upid);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Refresh failed");
    } finally {
      setBusyUpid(null);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Tasks"
        description="Tracked Proxmox UPIDs from mutation tools. Refresh pulls live status from the active host."
        actions={
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => void refresh().catch((err: Error) => setError(err.message))}
          >
            <RefreshCw className="size-3.5" />
            Reload
          </Button>
        }
      />

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {loading ? (
        <LoadingBlock label="Loading tasks…" />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={ListTodo}
          title="No tracked tasks"
          description="Mutation tools record UPIDs here when Proxmox returns a task identifier."
        />
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  UPID
                </TableHead>
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Operation
                </TableHead>
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Node
                </TableHead>
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Status
                </TableHead>
                <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Updated
                </TableHead>
                <TableHead className="h-8 px-3 text-right text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow
                  key={row.upid}
                  className={focusUpid === row.upid ? "bg-primary/5" : undefined}
                >
                  <TableCell className="max-w-[220px] truncate px-3 py-2 font-mono text-[11px]" title={row.upid}>
                    {row.upid}
                  </TableCell>
                  <TableCell className="px-3 py-2 font-mono text-[11px]">{row.operation}</TableCell>
                  <TableCell className="px-3 py-2 font-mono text-[11px]">
                    {row.node ?? "—"}
                  </TableCell>
                  <TableCell className="px-3 py-2 font-mono text-[11px]">
                    {row.status}
                    {row.last_observed_state ? (
                      <div className="text-[10px] text-muted-foreground">
                        {row.last_observed_state}
                      </div>
                    ) : null}
                  </TableCell>
                  <TableCell
                    className="px-3 py-2 font-mono text-[11px] text-muted-foreground"
                    title={formatLocal(row.updated_at)}
                  >
                    {relativeTime(row.updated_at)}
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right">
                    <Button
                      type="button"
                      size="xs"
                      variant="outline"
                      disabled={busyUpid === row.upid}
                      onClick={() => void onRefresh(row.upid)}
                    >
                      Refresh
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Audit events with <span className="font-mono">proxmox_task_upid</span> deep-link here via{" "}
        <NavLink to="/audit" className="underline underline-offset-2">
          Audit
        </NavLink>
        .
      </p>
    </div>
  );
}
