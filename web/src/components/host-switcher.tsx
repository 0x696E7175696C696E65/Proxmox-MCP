import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { NavLink } from "react-router-dom";
import {
  Check,
  ChevronDown,
  HardDrive,
  KeyRound,
  Loader2,
  Server,
} from "lucide-react";
import {
  AdminApi,
  type HostHealth,
  type ManagedHost,
} from "../api";
import { waitForAdminReady } from "../lib/wait-for-admin";
import { usePrivacy } from "../privacy";
import {
  HostRestartOverlay,
  type RestartOverlayPhase,
} from "@/components/host-restart-overlay";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FieldLabel } from "@/components/form-section";
import { cn } from "@/lib/utils";

export function shortHostLabel(endpoint: string): string {
  try {
    const u = new URL(endpoint);
    return u.host || endpoint;
  } catch {
    return endpoint.replace(/^https?:\/\//, "").split("/")[0] || endpoint;
  }
}

type HostCatalogState = {
  hosts: ManagedHost[];
  activeHostId: string | null;
  loading: boolean;
  error: string | null;
  successBanner: string | null;
  canSwitch: boolean;
  reload: () => Promise<void>;
  mergeHostHealth: (hostId: string, health: HostHealth) => void;
  requestActivate: (host: ManagedHost) => void;
  clearBanner: () => void;
};

const HostCatalogContext = createContext<HostCatalogState | null>(null);

export function useHostCatalog() {
  const ctx = useContext(HostCatalogContext);
  if (!ctx) {
    throw new Error("useHostCatalog requires HostCatalogProvider");
  }
  return ctx;
}

export function HostCatalogProvider({
  children,
  canSwitch,
}: {
  children: ReactNode;
  canSwitch: boolean;
}) {
  const [hosts, setHosts] = useState<ManagedHost[]>([]);
  const [activeHostId, setActiveHostId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);
  const [pending, setPending] = useState<ManagedHost | null>(null);
  const [stepUpPassword, setStepUpPassword] = useState("");
  const [activating, setActivating] = useState(false);
  const [overlay, setOverlay] = useState<{
    host: ManagedHost;
    phase: RestartOverlayPhase;
  } | null>(null);
  const pollGen = useRef(0);

  const reload = useCallback(async () => {
    try {
      const data = await AdminApi.hosts();
      setHosts((prev) => {
        const healthById = new Map(
          prev.map((h) => [h.host_id, h.health] as const),
        );
        return data.hosts.map((h) => ({
          ...h,
          health: h.health ?? healthById.get(h.host_id),
        }));
      });
      setActiveHostId(data.active_host_id);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load hosts");
    } finally {
      setLoading(false);
    }
  }, []);

  const mergeHostHealth = useCallback((hostId: string, health: HostHealth) => {
    setHosts((prev) =>
      prev.map((h) => (h.host_id === hostId ? { ...h, health } : h)),
    );
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const runWait = useCallback(
    async (host: ManagedHost) => {
      const gen = ++pollGen.current;
      setOverlay({ host, phase: "applying" });
      await new Promise((r) => window.setTimeout(r, 450));
      if (pollGen.current !== gen) return;
      setOverlay({ host, phase: "restarting" });
      await new Promise((r) => window.setTimeout(r, 500));
      if (pollGen.current !== gen) return;
      setOverlay({ host, phase: "reconnecting" });
      try {
        await waitForAdminReady();
        if (pollGen.current !== gen) return;
        setOverlay({ host, phase: "ready" });
        setSuccessBanner(`Now managing ${host.name}`);
        await reload();
        window.setTimeout(() => {
          if (pollGen.current === gen) setOverlay(null);
        }, 1800);
      } catch {
        if (pollGen.current !== gen) return;
        setOverlay({ host, phase: "timeout" });
      }
    },
    [reload],
  );

  const confirmActivate = useCallback(async () => {
    if (!pending) return;
    if (!stepUpPassword.trim()) {
      setError("Confirm your admin password to switch hosts");
      return;
    }
    const host = pending;
    setActivating(true);
    setError(null);
    try {
      await AdminApi.activateHost(host.host_id, stepUpPassword);
      setPending(null);
      setStepUpPassword("");
      await runWait(host);
    } catch (err) {
      // Connection drop is expected if the process exits before the response
      // finishes flushing — still enter the restart wait overlay.
      const message = err instanceof Error ? err.message : "Activate failed";
      const looksLikeDrop =
        /failed to fetch|network|load failed|connection|aborted/i.test(message) ||
        message === "Failed to fetch";
      setPending(null);
      setStepUpPassword("");
      if (looksLikeDrop) {
        setError(null);
        await runWait(host);
      } else {
        setError(message);
      }
    } finally {
      setActivating(false);
    }
  }, [pending, runWait, stepUpPassword]);

  const value = useMemo<HostCatalogState>(
    () => ({
      hosts,
      activeHostId,
      loading,
      error,
      successBanner,
      canSwitch,
      reload,
      mergeHostHealth,
      requestActivate: (host) => {
        if (host.host_id === activeHostId || !host.enabled) return;
        setError(null);
        setStepUpPassword("");
        setPending(host);
      },
      clearBanner: () => setSuccessBanner(null),
    }),
    [
      hosts,
      activeHostId,
      loading,
      error,
      successBanner,
      canSwitch,
      reload,
      mergeHostHealth,
    ],
  );

  return (
    <HostCatalogContext.Provider value={value}>
      {children}
      {pending ? (
        <SwitchHostConfirm
          host={pending}
          busy={activating}
          error={error}
          password={stepUpPassword}
          onPasswordChange={setStepUpPassword}
          onCancel={() => {
            if (!activating) {
              setPending(null);
              setStepUpPassword("");
              setError(null);
            }
          }}
          onConfirm={() => void confirmActivate()}
        />
      ) : null}
      {overlay ? (
        <HostRestartOverlay
          hostName={overlay.host.name}
          hostEndpoint={overlay.host.api_endpoint}
          phase={overlay.phase}
          onRetry={() => void runWait(overlay.host)}
        />
      ) : null}
    </HostCatalogContext.Provider>
  );
}

function SwitchHostConfirm({
  host,
  busy,
  error,
  password,
  onPasswordChange,
  onCancel,
  onConfirm,
}: {
  host: ManagedHost;
  busy: boolean;
  error: string | null;
  password: string;
  onPasswordChange: (value: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const { censor } = usePrivacy();
  const secretsOk = host.secrets_ready;

  return (
    <div className="fixed inset-0 z-[180] flex items-center justify-center px-4">
      <button
        type="button"
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
        aria-label="Cancel switch"
        disabled={busy}
        onClick={onCancel}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="switch-host-title"
        className="relative w-full max-w-md overflow-hidden rounded-lg border border-border bg-card shadow-2xl ring-1 ring-white/5"
      >
        <div className="space-y-3 border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="flex size-8 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/30">
              <HardDrive className="size-3.5 text-primary" />
            </div>
            <h2 id="switch-host-title" className="text-[14px] font-semibold tracking-tight">
              Switch managed server?
            </h2>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            After you confirm, the MCP process will restart so it manages only{" "}
            <span className="font-medium text-foreground">{host.name}</span> (
            <span className="font-mono text-[11px]">{censor(shortHostLabel(host.api_endpoint))}</span>
            ). The Admin UI will reconnect when MCP is back. Tools and inventory will no longer
            target the previous host.
          </p>
        </div>

        <div className="space-y-3 px-4 py-3">
          {!secretsOk ? (
            <Alert variant="destructive" className="py-2">
              <AlertDescription className="text-xs">
                Token missing for credential path{" "}
                <span className="font-mono">{censor(host.credential_ref_path)}</span>.{" "}
                <NavLink
                  to="/secrets"
                  className="font-medium underline underline-offset-2"
                  onClick={onCancel}
                >
                  Add token on Secrets
                </NavLink>
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="space-y-1.5">
            <FieldLabel htmlFor="switch-host-stepup">Admin password (step-up)</FieldLabel>
            <Input
              id="switch-host-stepup"
              type="password"
              value={password}
              onChange={(e) => onPasswordChange(e.target.value)}
              autoComplete="current-password"
              disabled={busy}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !busy && secretsOk && password.trim()) {
                  onConfirm();
                }
              }}
            />
            <p className="text-[11px] text-muted-foreground">
              Host switch restarts MCP — re-enter your admin password to confirm.
            </p>
          </div>

          {error ? (
            <Alert variant="destructive" className="py-2">
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onCancel}>
              Cancel
            </Button>
            <Button
              type="button"
              size="sm"
              disabled={busy || !secretsOk || !password.trim()}
              onClick={onConfirm}
            >
              {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
              Switch & restart
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function HealthDot({ host }: { host: ManagedHost }) {
  const health = host.health;
  const tone =
    health == null
      ? "bg-muted-foreground/40"
      : health.ok
        ? "bg-[oklch(0.72_0.15_155)]"
        : "bg-[oklch(0.75_0.16_75)]";
  const title =
    health == null
      ? "Health unknown"
      : health.ok
        ? `OK${health.version ? ` · ${health.version}` : ""}`
        : health.error || "Probe failed";
  return (
    <span
      className={cn("inline-block size-1.5 shrink-0 rounded-full", tone)}
      title={title}
      aria-label={title}
    />
  );
}

function SecretsBadge({ ready }: { ready: boolean }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-sm font-mono text-[9px] uppercase tracking-wide",
        ready
          ? "border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[oklch(0.78_0.14_155)]"
          : "text-muted-foreground",
      )}
    >
      {ready ? "secrets" : "no token"}
    </Badge>
  );
}

export function HostSwitcher() {
  const {
    hosts,
    activeHostId,
    loading,
    canSwitch,
    requestActivate,
    successBanner,
    clearBanner,
    error,
  } = useHostCatalog();
  const { censor } = usePrivacy();
  const [open, setOpen] = useState(false);
  const [flash, setFlash] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const prevActive = useRef<string | null>(null);

  const active = hosts.find((h) => h.host_id === activeHostId) ?? hosts[0] ?? null;
  const switcherHosts = useMemo(
    () =>
      hosts.filter(
        (h) => h.enabled || h.host_id === activeHostId,
      ),
    [hosts, activeHostId],
  );

  useEffect(() => {
    if (activeHostId && prevActive.current && prevActive.current !== activeHostId) {
      setFlash(true);
      const id = window.setTimeout(() => setFlash(false), 1200);
      prevActive.current = activeHostId;
      return () => window.clearTimeout(id);
    }
    prevActive.current = activeHostId;
  }, [activeHostId]);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    if (!successBanner) return;
    const id = window.setTimeout(() => clearBanner(), 6000);
    return () => window.clearTimeout(id);
  }, [successBanner, clearBanner]);

  return (
    <div className="relative flex items-center gap-2" ref={rootRef}>
      {successBanner ? (
        <div className="hidden max-w-[200px] truncate rounded-md border border-[oklch(0.72_0.15_155/0.35)] bg-[oklch(0.72_0.15_155/0.1)] px-2 py-1 text-[10px] text-[oklch(0.78_0.14_155)] lg:block animate-in fade-in slide-in-from-top-1 duration-300">
          {successBanner}
        </div>
      ) : null}

      <button
        type="button"
        className={cn(
          "flex max-w-[240px] items-center gap-2 rounded-md border border-border/70 bg-muted/20 px-2 py-1 text-left transition-all duration-300 hover:border-primary/40 hover:bg-primary/5",
          open && "border-primary/40 bg-primary/5",
          flash && "border-primary/60 bg-primary/10 ring-2 ring-primary/25",
        )}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label="Managed Proxmox server"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="relative">
          <Server className="size-3 shrink-0 text-primary" />
          {flash ? (
            <span className="absolute -inset-1 animate-ping rounded-full bg-primary/30" />
          ) : null}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
            Managing
          </span>
          <span
            key={active?.host_id ?? "none"}
            className="block truncate text-[11px] font-medium leading-tight animate-in fade-in slide-in-from-bottom-1 duration-300"
          >
            {loading ? "…" : active?.name ?? "No host"}
          </span>
          <span className="block truncate font-mono text-[10px] text-muted-foreground">
            {active ? censor(shortHostLabel(active.api_endpoint)) : "—"}
          </span>
        </span>
        <ChevronDown
          className={cn(
            "size-3.5 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-180",
          )}
        />
      </button>

      {open ? (
        <div
          role="listbox"
          className="absolute right-0 top-[calc(100%+6px)] z-[120] w-[320px] overflow-hidden rounded-lg border border-border bg-card shadow-2xl ring-1 ring-white/5"
        >
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Managed servers
            </span>
            {canSwitch ? (
              <Button asChild size="xs" variant="ghost" className="h-6 text-muted-foreground">
                <NavLink to="/servers" onClick={() => setOpen(false)}>
                  Manage
                </NavLink>
              </Button>
            ) : null}
          </div>

          {error ? (
            <p className="px-3 py-2 text-xs text-destructive">{error}</p>
          ) : null}

          <ul className="max-h-[280px] overflow-y-auto p-1.5">
            {switcherHosts.length === 0 ? (
              <li className="px-2 py-4 text-center text-xs text-muted-foreground">
                No hosts registered yet.
              </li>
            ) : (
              switcherHosts.map((host) => {
                const isActive = host.host_id === activeHostId;
                const canSelect = canSwitch && host.enabled && !isActive;
                return (
                  <li key={host.host_id}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={isActive}
                      disabled={!canSelect}
                      className={cn(
                        "flex w-full items-start gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors",
                        isActive
                          ? "bg-primary/10"
                          : canSelect
                            ? "hover:bg-muted/40"
                            : "opacity-70",
                      )}
                      onClick={() => {
                        if (!canSelect) return;
                        setOpen(false);
                        requestActivate(host);
                      }}
                    >
                      <HealthDot host={host} />
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-1.5">
                          <span className="truncate text-[12px] font-medium">{host.name}</span>
                          {isActive ? (
                            <Check className="size-3 shrink-0 text-primary" aria-label="Active" />
                          ) : null}
                        </span>
                        <span className="mt-0.5 block truncate font-mono text-[10px] text-muted-foreground">
                          {censor(host.api_endpoint)}
                        </span>
                        <span className="mt-1 flex flex-wrap items-center gap-1.5">
                          <SecretsBadge ready={host.secrets_ready} />
                          {isActive ? (
                            <Badge
                              variant="outline"
                              className="rounded-sm border-primary/35 bg-primary/10 font-mono text-[9px] uppercase text-primary"
                            >
                              Active
                            </Badge>
                          ) : null}
                          {!host.secrets_ready ? (
                            <span className="inline-flex items-center gap-0.5 text-[10px] text-muted-foreground">
                              <KeyRound className="size-2.5" />
                              needs token
                            </span>
                          ) : null}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })
            )}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
