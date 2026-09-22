import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { RefreshCw, ShieldCheck } from "lucide-react";
import { AdminApi, type ApprovalRow } from "../api";
import { formatLocal, relativeTime } from "../lib/format";
import { EmptyState } from "@/components/empty-state";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { RiskBadge } from "@/components/risk-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function ApprovalsPage() {
  const [rows, setRows] = useState<ApprovalRow[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [requireApproval, setRequireApproval] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [deciding, setDeciding] = useState<string | null>(null);
  const [policyBusy, setPolicyBusy] = useState(false);

  async function refresh() {
    const [approvals, policy] = await Promise.all([
      AdminApi.approvals(new URLSearchParams({ status: "pending" })),
      AdminApi.policy(),
    ]);
    setRows(approvals.approvals);
    const danger = policy.dangerous_operations ?? {};
    setEnabled(Boolean(danger.enabled));
    setRequireApproval(Boolean(danger.require_approval));
  }

  useEffect(() => {
    void refresh()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));

    const id = window.setInterval(() => {
      void refresh().catch(() => undefined);
    }, 15000);
    return () => window.clearInterval(id);
  }, []);

  async function savePolicy() {
    setError(null);
    setMessage(null);
    setPolicyBusy(true);
    try {
      await AdminApi.putPolicy({
        dangerous_operations_enabled: enabled,
        dangerous_operations_require_approval: requireApproval,
      });
      setMessage("Policy applied");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy update failed");
    } finally {
      setPolicyBusy(false);
    }
  }

  async function decide(id: string, decision: "approved" | "rejected") {
    setError(null);
    setDeciding(id);
    try {
      await AdminApi.decideApproval(id, decision);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decision failed");
    } finally {
      setDeciding(null);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Approvals"
        description="Pending dangerous-operation approvals and policy controls."
        actions={
          <Button size="sm" variant="outline" onClick={() => void refresh()}>
            <RefreshCw className="size-3.5" />
            Refresh
          </Button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <Card className="h-fit shadow-none">
          <CardHeader className="space-y-1 px-4 py-3">
            <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Policy
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              Gate high-risk MCP mutations before they execute.
            </p>
          </CardHeader>
          <CardContent className="space-y-3 px-4 pb-4">
            <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
              <Checkbox
                className="mt-0.5"
                checked={enabled}
                onCheckedChange={(v) => setEnabled(v === true)}
              />
              <span>
                <span className="font-medium text-foreground">Dangerous operations enabled</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  Allow high/critical tools when policy permits.
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
              <Checkbox
                className="mt-0.5"
                checked={requireApproval}
                onCheckedChange={(v) => setRequireApproval(v === true)}
              />
              <span>
                <span className="font-medium text-foreground">Require approval</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  Queue dangerous ops for explicit approve/deny.
                </span>
              </span>
            </label>
            <Button size="sm" className="w-full" disabled={policyBusy} onClick={() => void savePolicy()}>
              {policyBusy ? "Applying…" : "Apply policy"}
            </Button>
            {message ? (
              <Alert className="py-2">
                <AlertDescription className="text-xs text-[oklch(0.78_0.14_155)]">
                  {message}
                </AlertDescription>
              </Alert>
            ) : null}
          </CardContent>
        </Card>

        <div className="min-w-0 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Pending queue
            </h2>
            <span className="font-mono text-[11px] text-muted-foreground">{rows.length} open</span>
          </div>

          {error ? <p className="text-sm text-destructive">{error}</p> : null}

          {loading ? (
            <LoadingBlock label="Loading approvals…" />
          ) : rows.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title="No pending approvals"
              description="When an agent hits a gated dangerous operation, it will appear here for approve or deny."
              action={
                <Button asChild size="sm" variant="outline">
                  <NavLink to="/tools">Browse tools</NavLink>
                </Button>
              }
            />
          ) : (
            <div className="overflow-hidden rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                      Operation
                    </TableHead>
                    <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                      Actor
                    </TableHead>
                    <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                      Risk
                    </TableHead>
                    <TableHead className="h-8 px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                      Expires
                    </TableHead>
                    <TableHead className="h-8 px-3 text-right text-[10px] font-semibold uppercase tracking-[0.12em]">
                      Actions
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row) => {
                    const busyRow = deciding === row.approval_request_id;
                    return (
                      <TableRow key={row.approval_request_id}>
                        <TableCell className="px-3 py-2 font-mono text-[11px]">
                          {row.operation}
                        </TableCell>
                        <TableCell className="px-3 py-2 text-[12px]">
                          {row.actor_user_id}
                          <div className="font-mono text-[10px] text-muted-foreground">
                            {row.actor_agent_id}
                          </div>
                        </TableCell>
                        <TableCell className="px-3 py-2">
                          <RiskBadge risk={row.risk_level} />
                        </TableCell>
                        <TableCell
                          className="px-3 py-2 font-mono text-[11px] text-muted-foreground"
                          title={formatLocal(row.expires_at)}
                        >
                          {relativeTime(row.expires_at)}
                        </TableCell>
                        <TableCell className="px-3 py-2">
                          <div className="flex justify-end gap-1.5">
                            <Button
                              size="xs"
                              variant="outline"
                              disabled={busyRow}
                              onClick={() => void decide(row.approval_request_id, "approved")}
                            >
                              {busyRow ? "…" : "Approve"}
                            </Button>
                            <Button
                              size="xs"
                              variant="destructive"
                              disabled={busyRow}
                              onClick={() => void decide(row.approval_request_id, "rejected")}
                            >
                              Deny
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
