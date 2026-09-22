import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { CheckCircle2, Loader2, RefreshCw, Server } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type RestartOverlayPhase =
  | "applying"
  | "restarting"
  | "reconnecting"
  | "ready"
  | "timeout";

const PHASES: Array<{
  id: Exclude<RestartOverlayPhase, "ready" | "timeout">;
  label: string;
}> = [
  { id: "applying", label: "Apply host config" },
  { id: "restarting", label: "Restart MCP process" },
  { id: "reconnecting", label: "Reconnect Admin API" },
];

export function HostRestartOverlay({
  hostName,
  hostEndpoint,
  phase,
  onRetry,
}: {
  hostName: string;
  hostEndpoint?: string;
  phase: RestartOverlayPhase;
  onRetry: () => void;
}) {
  const [elapsedSec, setElapsedSec] = useState(0);

  useEffect(() => {
    setElapsedSec(0);
  }, [hostName]);

  useEffect(() => {
    if (phase === "ready" || phase === "timeout") return;
    const id = window.setInterval(() => {
      setElapsedSec((s) => s + 1);
    }, 1000);
    return () => window.clearInterval(id);
  }, [phase]);

  const activeIdx =
    phase === "applying" ? 0 : phase === "restarting" ? 1 : phase === "reconnecting" ? 2 : 3;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center bg-background/92 px-4 backdrop-blur-md animate-in fade-in duration-200"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="host-restart-title"
      aria-describedby="host-restart-desc"
    >
      <div className="w-full max-w-md space-y-4 rounded-lg border border-border bg-card p-6 shadow-2xl ring-1 ring-white/5 animate-in zoom-in-95 fade-in duration-300">
        {phase !== "ready" && phase !== "timeout" ? (
          <>
            <div className="flex items-start gap-3">
              <div className="relative flex size-11 shrink-0 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/35">
                <Server className="size-5 text-primary" />
                <span className="absolute -right-1 -top-1 flex size-4 items-center justify-center rounded-full bg-card ring-1 ring-primary/40">
                  <Loader2 className="size-2.5 animate-spin text-primary" />
                </span>
              </div>
              <div className="min-w-0 space-y-1">
                <h2 id="host-restart-title" className="text-[15px] font-semibold tracking-tight">
                  Switching managed server
                </h2>
                <p id="host-restart-desc" className="text-xs leading-relaxed text-muted-foreground">
                  Target{" "}
                  <span className="font-medium text-foreground">{hostName}</span>
                  {hostEndpoint ? (
                    <>
                      {" "}
                      <span className="font-mono text-[11px] text-muted-foreground">
                        ({hostEndpoint.replace(/^https?:\/\//, "")})
                      </span>
                    </>
                  ) : null}
                  . Tools will talk to this host only after reconnect.
                </p>
              </div>
            </div>

            <ol className="space-y-2 rounded-md border border-border/70 bg-muted/15 p-3">
              {PHASES.map((step, idx) => {
                const done = idx < activeIdx;
                const current = idx === activeIdx;
                return (
                  <li key={step.id} className="flex items-center gap-2.5">
                    <span
                      className={cn(
                        "flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold",
                        done && "bg-[oklch(0.72_0.15_155/0.25)] text-[oklch(0.78_0.14_155)]",
                        current && "bg-primary/20 text-primary ring-1 ring-primary/40",
                        !done && !current && "bg-muted text-muted-foreground",
                      )}
                    >
                      {done ? <CheckCircle2 className="size-3" /> : idx + 1}
                    </span>
                    <span
                      className={cn(
                        "text-[12px]",
                        current && "font-medium text-foreground",
                        done && "text-muted-foreground",
                        !done && !current && "text-muted-foreground/70",
                      )}
                    >
                      {step.label}
                      {current ? (
                        <span className="ml-2 inline-flex gap-0.5 align-middle">
                          <span className="size-1 animate-pulse rounded-full bg-primary" />
                          <span className="size-1 animate-pulse rounded-full bg-primary [animation-delay:150ms]" />
                          <span className="size-1 animate-pulse rounded-full bg-primary [animation-delay:300ms]" />
                        </span>
                      ) : null}
                    </span>
                  </li>
                );
              })}
            </ol>

            <div className="flex items-center justify-between rounded-md border border-border/70 bg-muted/20 px-3 py-2.5">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Elapsed
                </div>
                <div className="mt-0.5 font-mono text-[13px] tabular-nums">{elapsedSec}s</div>
              </div>
              <div className="h-1.5 w-28 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full animate-pulse rounded-full bg-primary/70"
                  style={{ width: `${Math.min(95, 18 + elapsedSec * 8)}%` }}
                />
              </div>
            </div>
          </>
        ) : null}

        {phase === "ready" ? (
          <Alert className="border-[oklch(0.72_0.15_155/0.35)] bg-[oklch(0.72_0.15_155/0.08)] py-3 animate-in fade-in zoom-in-95 duration-300">
            <CheckCircle2 className="size-4 text-[oklch(0.78_0.14_155)]" />
            <AlertTitle className="text-[oklch(0.78_0.14_155)]">Now managing {hostName}</AlertTitle>
            <AlertDescription className="text-xs text-muted-foreground">
              Admin API is back. Catalog, Overview, and tools target this host only.
            </AlertDescription>
          </Alert>
        ) : null}

        {phase === "timeout" ? (
          <div className="space-y-3">
            <Alert variant="destructive" className="py-3">
              <AlertTitle>Admin API not ready</AlertTitle>
              <AlertDescription className="text-xs">
                Restart may still be in progress. Check Runtime or retry the health poll.
              </AlertDescription>
            </Alert>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" onClick={onRetry}>
                <RefreshCw className="size-3.5" />
                Retry poll
              </Button>
              <Button asChild type="button" size="sm" variant="outline">
                <NavLink to="/runtime">Open Runtime</NavLink>
              </Button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
