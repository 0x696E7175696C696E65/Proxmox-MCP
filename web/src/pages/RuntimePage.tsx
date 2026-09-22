import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { Gauge, RefreshCw, RotateCcw } from "lucide-react";
import { AdminApi } from "../api";
import { FormSection } from "@/components/form-section";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

export function RuntimePage() {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const data = await AdminApi.runtime();
    setStatus(data);
  }

  useEffect(() => {
    void refresh().catch((err: Error) => setError(err.message));
  }, []);

  async function restart() {
    if (!window.confirm("Restart the MCP process now? Active sessions will drop briefly.")) return;
    setBusy(true);
    setError(null);
    try {
      await AdminApi.restart();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Restart requested");
    } finally {
      setBusy(false);
      window.setTimeout(() => {
        void refresh().catch(() => undefined);
      }, 2500);
    }
  }

  const restartRequired = Boolean(status?.restart_required);
  const message = String(status?.message ?? "idle");

  return (
    <div className="space-y-4">
      <PageHeader
        title="Runtime"
        description="Apply state and controlled process restart."
        actions={
          <Button size="sm" variant="outline" onClick={() => void refresh()}>
            <RefreshCw className="size-3.5" />
            Refresh
          </Button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
        <FormSection
          title="Process state"
          description="Hot-applied config stays live; some secret rotations need a restart."
          actions={
            <StatusBadge status={restartRequired ? "started" : "ok"} />
          }
        >
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="rounded-md border border-border/70 bg-muted/15 px-3 py-2.5">
              <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Restart required
              </div>
              <div className="mt-1 text-[13px] font-medium">
                {restartRequired ? "Yes — restart pending" : "No"}
              </div>
            </div>
            <div className="rounded-md border border-border/70 bg-muted/15 px-3 py-2.5">
              <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Message
              </div>
              <div className="mt-1 truncate font-mono text-[12px]">{message}</div>
            </div>
          </div>

          {error ? (
            <Alert className="py-2">
              <AlertDescription className="text-xs text-primary">{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap gap-2 border-t border-border/60 pt-3">
            <Button
              type="button"
              variant="destructive"
              size="sm"
              disabled={busy}
              onClick={() => void restart()}
            >
              <RotateCcw className="size-3.5" />
              {busy ? "Restarting…" : "Restart MCP"}
            </Button>
            {!restartRequired ? (
              <p className="self-center text-xs text-muted-foreground">
                Safe to leave running — no restart pending.
              </p>
            ) : (
              <p className="self-center text-xs text-primary">
                A config or secret change needs a process restart to take effect.
              </p>
            )}
          </div>
        </FormSection>

        <FormSection title="Related" description="Jump to settings that affect runtime.">
          <div className="flex flex-col gap-1.5">
            <Button asChild variant="outline" size="sm" className="justify-start">
              <NavLink to="/config">
                <Gauge className="size-3.5" />
                Config
              </NavLink>
            </Button>
            <Button asChild variant="outline" size="sm" className="justify-start">
              <NavLink to="/secrets">Secrets</NavLink>
            </Button>
            <Button asChild variant="outline" size="sm" className="justify-start">
              <NavLink to="/health">Health</NavLink>
            </Button>
          </div>
        </FormSection>
      </div>
    </div>
  );
}
