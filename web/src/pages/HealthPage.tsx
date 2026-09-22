import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, HeartPulse, RefreshCw, Stethoscope } from "lucide-react";
import { AdminApi } from "../api";
import { EmptyState } from "@/components/empty-state";
import { FormSection } from "@/components/form-section";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type Dep = { name: string; required: boolean; status: string; detail: string };

export function HealthPage() {
  const [deps, setDeps] = useState<Dep[]>([]);
  const [readyStatus, setReadyStatus] = useState<string>("—");
  const [issues, setIssues] = useState<Array<{ name: string; detail: string }> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  async function refresh() {
    const data = await AdminApi.healthDeps();
    const ready = (data.ready ?? {}) as Record<string, unknown>;
    setReadyStatus(String(ready.status ?? "—"));
    const dependencies = (ready.dependencies ?? {}) as Record<string, Dep>;
    setDeps(
      Object.entries(dependencies).map(([name, value]) => ({
        name,
        required: Boolean(value.required),
        status: String(value.status),
        detail: String(value.detail),
      })),
    );
  }

  useEffect(() => {
    void refresh()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function runDoctor() {
    setBusy(true);
    setError(null);
    try {
      const res = await AdminApi.healthDoctor();
      setIssues(res.issues);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Doctor failed");
    } finally {
      setBusy(false);
    }
  }

  const stats = useMemo(() => {
    const ok = deps.filter((d) => d.status === "ok").length;
    const bad = deps.length - ok;
    const requiredBad = deps.filter((d) => d.required && d.status !== "ok").length;
    return { ok, bad, requiredBad, total: deps.length };
  }, [deps]);

  const readyOk = readyStatus === "ready" || readyStatus === "ok";

  if (loading) return <LoadingBlock label="Loading health…" />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Health"
        description="Dependency matrix and doctor diagnostics."
        actions={
          <div className="flex items-center gap-2">
            <StatusBadge status={readyOk ? "ok" : "error"} />
            <Button size="sm" variant="outline" onClick={() => void refresh()}>
              <RefreshCw className="size-3.5" />
              Refresh
            </Button>
            <Button size="sm" disabled={busy} onClick={() => void runDoctor()}>
              <Stethoscope className="size-3.5" />
              {busy ? "Running…" : "Run doctor"}
            </Button>
          </div>
        }
      />
      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      <div className="grid gap-2.5 sm:grid-cols-3">
        <Card className="shadow-none">
          <CardContent className="space-y-1 px-4 py-3">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Ready
            </div>
            <div className="text-[13px] font-medium">{readyStatus}</div>
          </CardContent>
        </Card>
        <Card className="shadow-none">
          <CardContent className="space-y-1 px-4 py-3">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Dependencies OK
            </div>
            <div className="font-mono text-[13px]">
              {stats.ok}/{stats.total}
            </div>
          </CardContent>
        </Card>
        <Card className="shadow-none">
          <CardContent className="space-y-1 px-4 py-3">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Required failing
            </div>
            <div
              className={
                stats.requiredBad > 0
                  ? "font-mono text-[13px] text-destructive"
                  : "font-mono text-[13px]"
              }
            >
              {stats.requiredBad}
            </div>
          </CardContent>
        </Card>
      </div>

      <FormSection title="Dependencies" description={`Gateway readiness · ${readyStatus}`}>
        {deps.length === 0 ? (
          <EmptyState
            icon={HeartPulse}
            title="No dependencies reported"
            description="Refresh or run doctor once the gateway has finished starting."
            className="py-8"
          />
        ) : (
          <div className="-mx-4 overflow-hidden border-y border-border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="h-8 px-4 text-[10px] font-semibold uppercase tracking-[0.12em]">
                    Name
                  </TableHead>
                  <TableHead className="h-8 px-4 text-[10px] font-semibold uppercase tracking-[0.12em]">
                    Status
                  </TableHead>
                  <TableHead className="h-8 px-4 text-[10px] font-semibold uppercase tracking-[0.12em]">
                    Required
                  </TableHead>
                  <TableHead className="h-8 px-4 text-[10px] font-semibold uppercase tracking-[0.12em]">
                    Detail
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {deps.map((dep) => (
                  <TableRow key={dep.name}>
                    <TableCell className="px-4 py-2 font-mono text-[12px]">{dep.name}</TableCell>
                    <TableCell className="px-4 py-2">
                      <StatusBadge status={dep.status === "ok" ? "ok" : "error"} />
                    </TableCell>
                    <TableCell className="px-4 py-2 text-[12px] text-muted-foreground">
                      {dep.required ? "yes" : "no"}
                    </TableCell>
                    <TableCell className="max-w-[280px] whitespace-normal px-4 py-2 text-[12px] text-muted-foreground">
                      {dep.detail}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </FormSection>

      {issues ? (
        issues.length === 0 ? (
          <div className="flex items-center gap-2 rounded-md border border-dashed border-border/70 bg-muted/15 px-3 py-3 text-xs text-muted-foreground">
            <CheckCircle2 className="size-3.5 text-[oklch(0.78_0.14_155)]" />
            Doctor found no issues.
          </div>
        ) : (
          <Alert variant="destructive">
            <AlertTitle className="text-xs font-semibold">
              Doctor found {issues.length} issue(s)
            </AlertTitle>
            <AlertDescription className="mt-1 space-y-1 text-xs">
              {issues.map((i) => (
                <div key={i.name} className="font-mono">
                  {i.name}: {i.detail}
                </div>
              ))}
            </AlertDescription>
          </Alert>
        )
      ) : null}
    </div>
  );
}
