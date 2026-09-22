import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  Activity,
  CheckCircle2,
  HeartPulse,
  Server,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { AdminApi, type AuditEvent } from "../api";
import { useAuth } from "../auth";
import { formatLocal, relativeTime } from "../lib/format";
import { useShellStatus } from "../shell-status";
import { useHostCatalog } from "@/components/host-switcher";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { usePrivacy } from "../privacy";

export function OverviewPage() {
  const { user } = useAuth();
  const isAdmin = user?.role !== "operator";
  const shell = useShellStatus();
  const { hosts, activeHostId, loading: hostsLoading } = useHostCatalog();
  const { censor } = usePrivacy();
  const activeHost = hosts.find((h) => h.host_id === activeHostId) ?? null;
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void Promise.all([AdminApi.overview(), AdminApi.audit(new URLSearchParams({ limit: "10" }))])
      .then(([overview, audit]) => {
        setData(overview);
        setEvents(audit.events);
      })
      .catch((err: Error) => setError(err.message));
  }, [activeHostId]);

  if (error) return <p className="text-sm text-destructive">{error}</p>;
  if (!data) return <LoadingBlock label="Loading overview…" />;

  const config = (data.config ?? {}) as Record<string, unknown>;
  const runtime = (data.runtime ?? {}) as Record<string, unknown>;
  const health = (data.health ?? {}) as Record<string, unknown>;
  const failures = (data.recent_failures ?? []) as Array<Record<string, unknown>>;
  const healthStatus = String(health.status ?? shell.healthStatus);
  const healthOk = ["ok", "ready"].includes(healthStatus.toLowerCase());

  const managingName = activeHost?.name ?? "No managed host";
  const managingEndpoint = activeHost?.api_endpoint ?? "not configured";
  const managingId = activeHost?.host_id ?? "—";
  const managingTls = activeHost ? String(activeHost.tls_verify) : "—";

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        description="Ops cockpit — gateway health, activity, and shortcuts."
      />

      <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
        <StatusTile
          label="Health"
          value={healthStatus}
          badge={<StatusBadge status={healthOk ? "ok" : "error"} />}
        />
        <StatusTile
          label="Runtime"
          value={String(runtime.message ?? shell.runtimeMessage ?? "idle")}
          mono
          accent={shell.restartRequired}
        />
        <StatusTile
          label="Approvals"
          value={
            shell.pendingApprovals > 0
              ? `${shell.pendingApprovals} pending`
              : "Queue clear"
          }
          badge={
            shell.pendingApprovals > 0 ? (
              <StatusBadge status="started" />
            ) : (
              <StatusBadge status="ok" />
            )
          }
        />
        <StatusTile
          label="Environment"
          value={String(config.environment ?? "—")}
        />
      </div>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <ActionCard to="/tools" icon={Wrench} title="Tools" desc="Browse & invoke" />
        <ActionCard to="/audit" icon={Activity} title="Audit" desc="Live event stream" />
        <ActionCard to="/health" icon={HeartPulse} title="Health" desc="Deps & doctor" />
        <ActionCard
          to="/approvals"
          icon={ShieldCheck}
          title="Approvals"
          desc={shell.pendingApprovals > 0 ? `${shell.pendingApprovals} waiting` : "Policy & queue"}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="shadow-none">
          <CardHeader className="flex flex-row items-center justify-between gap-3 space-y-0 px-4 py-3">
            <div className="flex items-center gap-2">
              <Server className="size-3.5 text-muted-foreground" />
              <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Managing
              </CardTitle>
            </div>
            {isAdmin ? (
              <Button asChild size="xs" variant="ghost" className="text-muted-foreground">
                <NavLink to="/servers">Servers</NavLink>
              </Button>
            ) : null}
          </CardHeader>
          <CardContent className="space-y-1 px-4 pb-4 pt-0">
            {hostsLoading ? (
              <p className="text-xs text-muted-foreground">Resolving active host…</p>
            ) : (
              <div
                key={managingId}
                className="space-y-1 animate-in fade-in slide-in-from-bottom-1 duration-300"
              >
                <div className="flex items-center gap-2">
                  <p className="text-[13px] font-medium text-foreground">{managingName}</p>
                  {activeHost ? (
                    <span
                      className="inline-block size-1.5 animate-pulse rounded-full bg-[oklch(0.72_0.15_155)] shadow-[0_0_6px_oklch(0.72_0.15_155)]"
                      title="Active managed host"
                      aria-label="Active"
                    />
                  ) : null}
                </div>
                <p className="font-mono text-[12px] text-foreground">
                  {censor(managingEndpoint)}
                </p>
                <p className="text-xs text-muted-foreground">
                  TLS verify: {managingTls} · Auth: {String(config.auth_mode)} · id {managingId}
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="shadow-none">
          <CardHeader className="flex flex-row items-center justify-between gap-3 space-y-0 px-4 py-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="size-3.5 text-muted-foreground" />
              <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Recent failures
              </CardTitle>
            </div>
            <Button asChild size="xs" variant="ghost" className="text-muted-foreground">
              <NavLink to="/audit">Open audit</NavLink>
            </Button>
          </CardHeader>
          <CardContent className="px-4 pb-4 pt-0">
            {failures.length === 0 ? (
              <div className="flex items-center gap-2 rounded-md border border-dashed border-border/70 bg-muted/15 px-3 py-4 text-xs text-muted-foreground">
                <CheckCircle2 className="size-3.5 text-[oklch(0.78_0.14_155)]" />
                No recent failures — gateway looks clean.
              </div>
            ) : (
              <ul className="divide-y divide-border/60 overflow-hidden rounded-md border border-border">
                {failures.map((f) => {
                  const status = String(f.result_status ?? "error");
                  const tool = String(f.tool_name ?? "—");
                  const ts = String(f.timestamp ?? "");
                  return (
                    <li key={String(f.event_id)}>
                      <NavLink
                        to="/audit"
                        className="flex items-center gap-3 px-3 py-2.5 transition-colors hover:bg-muted/30"
                      >
                        <StatusBadge status={status} />
                        <div className="min-w-0 flex-1">
                          <div className="truncate font-mono text-[12px]">{tool}</div>
                          <div className="truncate font-mono text-[10px] text-muted-foreground">
                            {ts ? `${relativeTime(ts)} · ${formatLocal(ts)}` : "—"}
                          </div>
                        </div>
                      </NavLink>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="shadow-none">
        <CardHeader className="flex flex-row items-center justify-between gap-3 space-y-0 px-4 py-3">
          <div className="flex items-center gap-2">
            <Activity className="size-3.5 text-muted-foreground" />
            <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Recent activity
            </CardTitle>
          </div>
          <Button asChild size="xs" variant="ghost" className="text-muted-foreground">
            <NavLink to="/audit">View all</NavLink>
          </Button>
        </CardHeader>
        <CardContent className="px-4 pb-4 pt-0">
          {events.length === 0 ? (
            <p className="text-xs text-muted-foreground">No audit events yet.</p>
          ) : (
            <ul className="divide-y divide-border/60 overflow-hidden rounded-md border border-border">
              {events.map((event) => (
                <li
                  key={event.event_id}
                  className="flex items-center gap-3 px-3 py-2.5"
                >
                  <StatusBadge status={event.result_status} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[12px]">{event.tool_name}</div>
                    <div className="truncate text-[11px] text-muted-foreground">
                      {event.actor_user_id} · {relativeTime(event.timestamp)}
                    </div>
                  </div>
                  <div className="font-mono text-[10px] text-muted-foreground">
                    {event.duration_ms != null ? `${event.duration_ms}ms` : "—"}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatusTile({
  label,
  value,
  mono,
  badge,
  accent,
}: {
  label: string;
  value: string;
  mono?: boolean;
  badge?: ReactNode;
  accent?: boolean;
}) {
  return (
    <Card className={accent ? "border-primary/40 shadow-none" : "shadow-none"}>
      <CardContent className="space-y-1.5 px-4 py-3">
        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          {label}
        </div>
        <div className="flex items-center justify-between gap-2">
          <div
            className={
              mono
                ? "truncate font-mono text-[12px]"
                : "truncate text-[13px] font-medium"
            }
          >
            {value}
          </div>
          {badge}
        </div>
      </CardContent>
    </Card>
  );
}

function ActionCard({
  to,
  icon: Icon,
  title,
  desc,
}: {
  to: string;
  icon: typeof Wrench;
  title: string;
  desc: string;
}) {
  return (
    <NavLink
      to={to}
      className="group flex items-center gap-3 rounded-md border border-border bg-card/40 px-3 py-3 transition-colors hover:border-primary/40 hover:bg-primary/5"
    >
      <div className="flex size-8 items-center justify-center rounded-md bg-muted/40 ring-1 ring-border/60 group-hover:bg-primary/15 group-hover:ring-primary/30">
        <Icon className="size-3.5 text-muted-foreground group-hover:text-primary" />
      </div>
      <div className="min-w-0">
        <div className="text-[13px] font-medium">{title}</div>
        <div className="truncate text-[11px] text-muted-foreground">{desc}</div>
      </div>
    </NavLink>
  );
}
