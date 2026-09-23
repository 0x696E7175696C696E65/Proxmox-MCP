import { useEffect, useMemo, useState } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { Copy, RefreshCw, ShieldCheck } from "lucide-react";
import { AdminApi, type ApprovalRow } from "../api";
import { useAuth } from "../auth";
import { formatLocal, relativeTime } from "../lib/format";
import { EmptyState } from "@/components/empty-state";
import { FieldLabel } from "@/components/form-section";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { RiskBadge } from "@/components/risk-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
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

type StatusFilter = "pending" | "all";

type StepUpAction =
  | { kind: "policy" }
  | { kind: "decide"; id: string; decision: "approved" | "rejected" };

export function ApprovalsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [searchParams, setSearchParams] = useSearchParams();
  const deepLinkId = searchParams.get("id");
  const [rows, setRows] = useState<ApprovalRow[]>([]);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("pending");
  const [enabled, setEnabled] = useState(true);
  const [requireApproval, setRequireApproval] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ApprovalRow | null>(null);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [retryHint, setRetryHint] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<StepUpAction | null>(null);
  const [stepUpPassword, setStepUpPassword] = useState("");
  const [stepUpReason, setStepUpReason] = useState("");
  const [stepUpBusy, setStepUpBusy] = useState(false);

  const pendingCount = useMemo(
    () => rows.filter((r) => r.status === "pending").length,
    [rows],
  );

  async function refresh() {
    const params =
      statusFilter === "pending"
        ? new URLSearchParams({ status: "pending" })
        : undefined;
    const [approvals, policy] = await Promise.all([
      AdminApi.approvals(params),
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
  }, [statusFilter]);

  useEffect(() => {
    const intervalMs = pendingCount > 0 ? 5000 : 15000;
    const id = window.setInterval(() => {
      void refresh().catch(() => undefined);
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [pendingCount, statusFilter]);

  useEffect(() => {
    if (!deepLinkId) return;
    void AdminApi.approval(deepLinkId)
      .then((resp) => setSelected(resp.approval))
      .catch((err: Error) => setError(err.message));
  }, [deepLinkId]);

  useEffect(() => {
    return () => {
      setIssuedToken(null);
      setRetryHint(null);
    };
  }, []);

  function openDetail(row: ApprovalRow) {
    setSelected(row);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("id", row.approval_request_id);
      return next;
    });
  }

  function closeDetail() {
    setSelected(null);
    setIssuedToken(null);
    setRetryHint(null);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("id");
      return next;
    });
  }

  function openStepUp(action: StepUpAction) {
    setError(null);
    setMessage(null);
    setStepUpPassword("");
    setStepUpReason("");
    setStepUp(action);
  }

  async function submitStepUp() {
    if (stepUp === null) return;
    setStepUpBusy(true);
    setError(null);
    try {
      if (stepUp.kind === "policy") {
        await AdminApi.putPolicy({
          dangerous_operations_enabled: enabled,
          dangerous_operations_require_approval: requireApproval,
          password: stepUpPassword,
        });
        setMessage("Policy applied — live Settings updated immediately");
        setStepUp(null);
        await refresh();
        return;
      }
      const result = await AdminApi.decideApproval(stepUp.id, {
        decision: stepUp.decision,
        password: stepUpPassword,
        reason: stepUpReason.trim() || undefined,
      });
      setStepUp(null);
      if (result.approval_token) {
        setIssuedToken(result.approval_token);
        setRetryHint(result.retry_hint ?? null);
        setMessage("Approved — copy the one-time token now; it is shown once.");
      } else {
        setIssuedToken(null);
        setRetryHint(null);
        setMessage(stepUp.decision === "rejected" ? "Request denied" : "Decision recorded");
      }
      setSelected(result.approval);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setStepUpBusy(false);
    }
  }

  async function copyToken() {
    if (!issuedToken) return;
    try {
      await navigator.clipboard.writeText(issuedToken);
      setMessage("Token copied to clipboard");
    } catch {
      setError("Clipboard copy failed — select the token manually");
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Approvals"
        description="Pending dangerous-operation queue, decide with step-up, and live policy."
        actions={
          <Button size="sm" variant="outline" onClick={() => void refresh()}>
            <RefreshCw className="size-3.5" />
            Refresh
          </Button>
        }
      />

      {issuedToken ? (
        <Alert className="border-primary/40 bg-primary/5 py-3">
          <AlertTitle className="text-sm">One-time approval token</AlertTitle>
          <AlertDescription className="mt-2 space-y-2">
            <p className="text-xs text-muted-foreground">
              Agents should retry with{" "}
              <span className="font-mono">options.approval_request_id</span> (no token paste).
              Token below is optional for non-agent clients and is shown once — never store in audit
              logs.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <code className="max-w-full break-all rounded-md border border-border bg-muted/40 px-2 py-1.5 font-mono text-[11px]">
                {issuedToken}
              </code>
              <Button type="button" size="sm" variant="outline" onClick={() => void copyToken()}>
                <Copy className="size-3.5" />
                Copy
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => {
                  setIssuedToken(null);
                  setRetryHint(null);
                }}
              >
                Dismiss
              </Button>
            </div>
            {retryHint ? (
              <p className="text-xs text-muted-foreground">{retryHint}</p>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <Card className="h-fit shadow-none">
          <CardHeader className="space-y-1 px-4 py-3">
            <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Policy
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              Live MCP guard switches — no restart. These gate high/critical tools before the
              Approvals queue.
            </p>
          </CardHeader>
          <CardContent className="space-y-3 px-4 pb-4">
            {!isAdmin ? (
              <Alert className="py-2">
                <AlertDescription className="text-xs text-muted-foreground">
                  Operators can view the queue; only admins change policy or decide requests.
                </AlertDescription>
              </Alert>
            ) : null}
            <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
              <Checkbox
                className="mt-0.5"
                checked={enabled}
                disabled={!isAdmin}
                onCheckedChange={(v) => setEnabled(v === true)}
              />
              <span>
                <span className="font-medium text-foreground">Dangerous operations enabled</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  Master switch. Off = all high/critical tools hard-denied (no queue).
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
              <Checkbox
                className="mt-0.5"
                checked={requireApproval}
                disabled={!isAdmin}
                onCheckedChange={(v) => setRequireApproval(v === true)}
              />
              <span>
                <span className="font-medium text-foreground">Require approval</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  On = queue for admin approve/deny. Off = dangerous tools run if ACL allows
                  (still audited).
                </span>
              </span>
            </label>
            {isAdmin ? (
              <Button
                size="sm"
                className="w-full"
                onClick={() => openStepUp({ kind: "policy" })}
              >
                Apply policy
              </Button>
            ) : null}
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
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Approvals
            </h2>
            <div className="flex items-center gap-2">
              <div className="flex rounded-md border border-border/80 p-0.5">
                <Button
                  type="button"
                  size="xs"
                  variant={statusFilter === "pending" ? "secondary" : "ghost"}
                  onClick={() => setStatusFilter("pending")}
                >
                  Pending
                </Button>
                <Button
                  type="button"
                  size="xs"
                  variant={statusFilter === "all" ? "secondary" : "ghost"}
                  onClick={() => setStatusFilter("all")}
                >
                  Recent
                </Button>
              </div>
              <span className="font-mono text-[11px] text-muted-foreground">
                {pendingCount} open
              </span>
            </div>
          </div>

          {error ? <p className="text-sm text-destructive">{error}</p> : null}

          {loading ? (
            <LoadingBlock label="Loading approvals…" />
          ) : rows.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title="No approvals in this view"
              description="When an agent hits a gated mutation, a pending row is minted with an approval_request_id. Approve so the agent can retry with that id (closed-loop; no token paste). A one-time token remains available for non-agent clients."
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
                      Status
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
                  {rows.map((row) => (
                    <TableRow
                      key={row.approval_request_id}
                      className="cursor-pointer"
                      onClick={() => openDetail(row)}
                    >
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
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {row.status}
                        {(row.required_approvals ?? 1) > 1 ? (
                          <div className="text-[10px] text-muted-foreground">
                            {row.approval_count ?? 0}/{row.required_approvals} quorum
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell
                        className="px-3 py-2 font-mono text-[11px] text-muted-foreground"
                        title={formatLocal(row.expires_at)}
                      >
                        {relativeTime(row.expires_at)}
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <div
                          className="flex justify-end gap-1.5"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {isAdmin && row.status === "pending" ? (
                            <>
                              <Button
                                size="xs"
                                variant="outline"
                                onClick={() =>
                                  openStepUp({
                                    kind: "decide",
                                    id: row.approval_request_id,
                                    decision: "approved",
                                  })
                                }
                              >
                                Approve
                              </Button>
                              <Button
                                size="xs"
                                variant="destructive"
                                onClick={() =>
                                  openStepUp({
                                    kind: "decide",
                                    id: row.approval_request_id,
                                    decision: "rejected",
                                  })
                                }
                              >
                                Deny
                              </Button>
                            </>
                          ) : (
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={() => openDetail(row)}
                            >
                              Detail
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      </div>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && closeDetail()}>
        <SheetContent side="right" className="w-full sm:max-w-md">
          {selected ? (
            <>
              <SheetHeader>
                <SheetTitle className="font-mono text-sm">{selected.operation}</SheetTitle>
                <SheetDescription>
                  Request {selected.approval_request_id}
                </SheetDescription>
              </SheetHeader>
              <div className="space-y-3 px-4 text-[13px]">
                <DetailRow label="Status" value={selected.status} />
                <DetailRow
                  label="Quorum"
                  value={`${selected.approval_count ?? 0}/${selected.required_approvals ?? 1}`}
                />
                <DetailRow
                  label="Actor"
                  value={`${selected.actor_user_id} / ${selected.actor_agent_id}`}
                />
                <DetailRow label="Risk" value={`${selected.risk_level} (${selected.risk_score})`} />
                <DetailRow label="Expires" value={formatLocal(selected.expires_at)} />
                {selected.decided_by ? (
                  <DetailRow label="Decided by" value={selected.decided_by} />
                ) : null}
                {selected.reason ? <DetailRow label="Reason" value={selected.reason} /> : null}
                {selected.summary ? (
                  <div className="space-y-1">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                      Summary
                    </div>
                    <pre className="overflow-auto rounded-md border border-border/70 bg-muted/20 p-2 font-mono text-[11px]">
                      {JSON.stringify(selected.summary, null, 2)}
                    </pre>
                  </div>
                ) : null}
              </div>
              {isAdmin && selected.status === "pending" ? (
                <SheetFooter>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      openStepUp({
                        kind: "decide",
                        id: selected.approval_request_id,
                        decision: "approved",
                      })
                    }
                  >
                    Approve
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() =>
                      openStepUp({
                        kind: "decide",
                        id: selected.approval_request_id,
                        decision: "rejected",
                      })
                    }
                  >
                    Deny
                  </Button>
                </SheetFooter>
              ) : null}
            </>
          ) : null}
        </SheetContent>
      </Sheet>

      {stepUp ? (
        <div
          className="fixed inset-0 z-[180] flex items-center justify-center bg-background/80 px-4 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-labelledby="approval-stepup-title"
        >
          <div className="w-full max-w-sm space-y-3 rounded-lg border border-border bg-card p-5 shadow-xl">
            <div>
              <h2 id="approval-stepup-title" className="text-[15px] font-semibold">
                {stepUp.kind === "policy"
                  ? "Confirm policy change"
                  : stepUp.decision === "approved"
                    ? "Approve request"
                    : "Deny request"}
              </h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Re-enter your admin password to continue.
              </p>
            </div>
            <div className="space-y-1.5">
              <FieldLabel htmlFor="approval-stepup-password">Password</FieldLabel>
              <Input
                id="approval-stepup-password"
                type="password"
                className="h-8"
                value={stepUpPassword}
                onChange={(e) => setStepUpPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            </div>
            {stepUp.kind === "decide" ? (
              <div className="space-y-1.5">
                <FieldLabel htmlFor="approval-stepup-reason">Reason (optional)</FieldLabel>
                <Input
                  id="approval-stepup-reason"
                  className="h-8"
                  value={stepUpReason}
                  onChange={(e) => setStepUpReason(e.target.value)}
                />
              </div>
            ) : null}
            {error ? <p className="text-xs text-destructive">{error}</p> : null}
            <div className="flex justify-end gap-2 pt-1">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={stepUpBusy}
                onClick={() => setStepUp(null)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                size="sm"
                disabled={stepUpBusy || !stepUpPassword}
                onClick={() => void submitStepUp()}
              >
                {stepUpBusy ? "Working…" : "Confirm"}
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 break-all font-mono text-[12px]">{value}</div>
    </div>
  );
}
