import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { Gauge, RefreshCw, RotateCcw } from "lucide-react";
import { AdminApi } from "../api";
import {
  HostRestartOverlay,
  type RestartOverlayPhase,
} from "@/components/host-restart-overlay";
import { FieldLabel, FormSection } from "@/components/form-section";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { waitForAdminReady } from "../lib/wait-for-admin";

export function RuntimePage() {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showStepUp, setShowStepUp] = useState(false);
  const [password, setPassword] = useState("");
  const [overlayPhase, setOverlayPhase] = useState<RestartOverlayPhase | null>(null);

  async function refresh() {
    const data = await AdminApi.runtime();
    setStatus(data);
  }

  useEffect(() => {
    void refresh().catch((err: Error) => setError(err.message));
  }, []);

  async function runRestart() {
    setBusy(true);
    setError(null);
    setOverlayPhase("applying");
    try {
      setOverlayPhase("restarting");
      try {
        await AdminApi.restart(password);
      } catch {
        // Network drop mid-restart is expected.
      }
      setShowStepUp(false);
      setPassword("");
      setOverlayPhase("reconnecting");
      await waitForAdminReady();
      setOverlayPhase("ready");
      await refresh();
      window.setTimeout(() => setOverlayPhase(null), 1600);
    } catch (err) {
      setOverlayPhase("timeout");
      setError(err instanceof Error ? err.message : "Restart reconnect timed out");
    } finally {
      setBusy(false);
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
          actions={<StatusBadge status={restartRequired ? "started" : "ok"} />}
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
              onClick={() => {
                setPassword("");
                setError(null);
                setShowStepUp(true);
              }}
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
                {message || "A config or secret change needs a process restart to take effect."}
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

      {showStepUp && overlayPhase === null ? (
        <div
          className="fixed inset-0 z-[180] flex items-center justify-center bg-background/80 px-4 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-labelledby="runtime-stepup-title"
        >
          <div className="w-full max-w-sm space-y-3 rounded-lg border border-border bg-card p-5 shadow-xl">
            <div>
              <h2 id="runtime-stepup-title" className="text-[15px] font-semibold">
                Confirm process restart
              </h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Active sessions will drop briefly. Re-enter your admin password.
              </p>
            </div>
            <div className="space-y-1.5">
              <FieldLabel htmlFor="runtime-stepup-password">Password</FieldLabel>
              <Input
                id="runtime-stepup-password"
                type="password"
                className="h-8"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            </div>
            {error ? <p className="text-xs text-destructive">{error}</p> : null}
            <div className="flex justify-end gap-2 pt-1">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => setShowStepUp(false)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                size="sm"
                variant="destructive"
                disabled={busy || !password}
                onClick={() => void runRestart()}
              >
                {busy ? "Restarting…" : "Restart now"}
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {overlayPhase ? (
        <HostRestartOverlay
          mode="process"
          hostName="MCP"
          phase={overlayPhase}
          onRetry={() => {
            void (async () => {
              setOverlayPhase("reconnecting");
              try {
                await waitForAdminReady();
                setOverlayPhase("ready");
                await refresh().catch(() => undefined);
                window.setTimeout(() => setOverlayPhase(null), 1600);
              } catch {
                setOverlayPhase("timeout");
              }
            })();
          }}
        />
      ) : null}
    </div>
  );
}
