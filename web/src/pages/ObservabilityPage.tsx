import { useEffect, useState } from "react";
import { Activity, Radar } from "lucide-react";
import { AdminApi } from "../api";
import { EmptyState } from "@/components/empty-state";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function ObservabilityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [configured, setConfigured] = useState(false);
  const [alerts, setAlerts] = useState<Array<Record<string, unknown>>>([]);
  const [trends, setTrends] = useState<Array<Record<string, unknown>>>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [amConfigured, setAmConfigured] = useState(false);
  const [promConfigured, setPromConfigured] = useState(false);

  async function refresh() {
    const data = await AdminApi.observabilityOverview();
    setConfigured(data.configured);
    setAlerts(data.alerts ?? []);
    setTrends(data.trends ?? []);
    setErrors(data.errors ?? []);
    setAmConfigured(Boolean(data.alertmanager?.configured));
    setPromConfigured(Boolean(data.prometheus?.configured));
  }

  useEffect(() => {
    void refresh()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingBlock label="Loading observability…" />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Observability"
        description="Alertmanager alerts and Prometheus trends when configured. No synthetic data."
        actions={
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => void refresh().catch((err: Error) => setError(err.message))}
          >
            Reload
          </Button>
        }
      />

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {errors.length > 0 ? (
        <p className="text-xs text-muted-foreground">Backend notes: {errors.join("; ")}</p>
      ) : null}

      {!configured ? (
        <EmptyState
          icon={Radar}
          title="Observability not configured"
          description="Set PROXMOX_MCP_OBSERVABILITY__ALERTMANAGER_URL and/or PROXMOX_MCP_OBSERVABILITY__PROMETHEUS_URL (https only)."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="shadow-none">
            <CardHeader className="px-4 py-3">
              <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Alertmanager {amConfigured ? "(configured)" : "(unset)"}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-0 pb-0">
              {!amConfigured ? (
                <p className="px-4 pb-4 text-xs text-muted-foreground">Not configured.</p>
              ) : alerts.length === 0 ? (
                <p className="px-4 pb-4 text-xs text-muted-foreground">No active alerts.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="h-8 px-3 text-[10px] uppercase">Alert</TableHead>
                      <TableHead className="h-8 px-3 text-[10px] uppercase">Severity</TableHead>
                      <TableHead className="h-8 px-3 text-[10px] uppercase">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.map((alert, idx) => (
                      <TableRow key={String(alert.fingerprint ?? alert.name ?? idx)}>
                        <TableCell className="px-3 py-2 font-mono text-[11px]">
                          {String(alert.name ?? "—")}
                        </TableCell>
                        <TableCell className="px-3 py-2 font-mono text-[11px]">
                          {String(alert.severity ?? "—")}
                        </TableCell>
                        <TableCell className="px-3 py-2 font-mono text-[11px]">
                          {String(alert.status ?? "—")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card className="shadow-none">
            <CardHeader className="px-4 py-3">
              <CardTitle className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                <Activity className="size-3.5" />
                Prometheus {promConfigured ? "(configured)" : "(unset)"}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 px-4 pb-4">
              {!promConfigured ? (
                <p className="text-xs text-muted-foreground">Not configured.</p>
              ) : trends.length === 0 ? (
                <p className="text-xs text-muted-foreground">No trend samples returned.</p>
              ) : (
                trends.map((trend, idx) => {
                  const samples = (trend.samples as Array<Record<string, unknown>>) ?? [];
                  return (
                    <div key={String(trend.metric ?? idx)} className="space-y-1">
                      <div className="font-mono text-[11px]">{String(trend.metric)}</div>
                      <div className="flex h-8 items-end gap-0.5">
                        {samples.slice(-24).map((sample, sidx) => {
                          const value = Number(sample.value ?? 0);
                          const height = Math.max(2, Math.min(32, value * 16 + 2));
                          return (
                            <span
                              key={sidx}
                              className="w-1.5 rounded-sm bg-primary/70"
                              style={{ height }}
                              title={String(sample.value ?? "")}
                            />
                          );
                        })}
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
