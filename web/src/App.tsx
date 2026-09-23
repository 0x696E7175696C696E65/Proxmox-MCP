import { Navigate, NavLink, Route, Routes } from "react-router-dom";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  FileKey2,
  Gauge,
  HardDrive,
  HeartPulse,
  KeyRound,
  LayoutDashboard,
  ListTodo,
  Radar,
  Server,
  Settings2,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { useAuth } from "./auth";
import { AdminApi } from "./api";
import { ShellStatusContext, type ShellStatus } from "./shell-status";
import { LoginPage } from "./pages/LoginPage";
import { OverviewPage } from "./pages/OverviewPage";
import { AuditPage } from "./pages/AuditPage";
import { SecretsPage } from "./pages/SecretsPage";
import { ConfigPage } from "./pages/ConfigPage";
import { RuntimePage } from "./pages/RuntimePage";
import { ToolsPage } from "./pages/ToolsPage";
import { HealthPage } from "./pages/HealthPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { ServersPage } from "./pages/ServersPage";
import { TasksPage } from "./pages/TasksPage";
import { InventoryPage } from "./pages/InventoryPage";
import { ObservabilityPage } from "./pages/ObservabilityPage";
import { AccessPage } from "./pages/AccessPage";
import { AppSidebar } from "@/components/app-sidebar";
import { AppTopBar } from "@/components/app-topbar";
import { CommandPalette } from "@/components/command-palette";
import { HostCatalogProvider } from "@/components/host-switcher";
import { LoadingBlock } from "@/components/loading-block";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TooltipProvider } from "@/components/ui/tooltip";
import { PrivacyProvider } from "./privacy";

function Shell() {
  const { user, logout } = useAuth();
  const [shell, setShell] = useState<ShellStatus>({
    healthStatus: "—",
    runtimeMessage: "—",
    restartRequired: false,
    restartMsg: "",
    pendingApprovals: 0,
  });
  const [navOpen, setNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const tick = useCallback(async () => {
    try {
      const [runtime, approvals, health] = await Promise.all([
        AdminApi.runtime(),
        AdminApi.approvals(new URLSearchParams({ status: "pending" })),
        AdminApi.healthDeps().catch(() => null),
      ]);
      const ready = ((health?.ready ?? {}) as Record<string, unknown>).status;
      setShell({
        healthStatus: String(ready ?? "—"),
        runtimeMessage: String(runtime.message ?? "idle"),
        restartRequired: Boolean(runtime.restart_required),
        restartMsg: String(runtime.message ?? ""),
        pendingApprovals: approvals.approvals?.length ?? 0,
      });
    } catch {
      /* ignore transient */
    }
  }, []);

  useEffect(() => {
    void tick();
    const id = window.setInterval(() => void tick(), 20000);
    return () => window.clearInterval(id);
  }, [tick]);

  const isAdmin = user?.role === "admin";
  const navGroups = useMemo(
    () => [
      {
        label: "Observe",
        items: [
          { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
          { to: "/inventory", label: "Inventory", icon: Server },
          { to: "/tasks", label: "Tasks", icon: ListTodo },
          { to: "/audit", label: "Audit", icon: Activity },
          { to: "/health", label: "Health", icon: HeartPulse },
          { to: "/observability", label: "Observability", icon: Radar },
        ],
      },
      {
        label: "Control",
        items: [
          { to: "/tools", label: "Tools", icon: Wrench },
          {
            to: "/approvals",
            label: "Approvals",
            icon: ShieldCheck,
            badge: shell.pendingApprovals > 0 ? shell.pendingApprovals : null,
          },
          ...(isAdmin
            ? [
                { to: "/access", label: "Access", icon: KeyRound },
                { to: "/servers", label: "Servers", icon: HardDrive },
                { to: "/secrets", label: "Secrets", icon: FileKey2 },
                { to: "/config", label: "Config", icon: Settings2 },
                { to: "/runtime", label: "Runtime", icon: Gauge },
              ]
            : [{ to: "/config", label: "Config", icon: Settings2 }]),
        ],
      },
    ],
    [shell.pendingApprovals, isAdmin],
  );

  return (
    <ShellStatusContext.Provider value={shell}>
      <HostCatalogProvider canSwitch={isAdmin}>
        <div className="flex min-h-svh bg-background">
          <AppSidebar
            groups={navGroups}
            username={user?.username}
            onLogout={() => void logout()}
            mobileOpen={navOpen}
            onMobileClose={() => setNavOpen(false)}
          />

          <div className="flex min-w-0 flex-1 flex-col">
            <AppTopBar
              onOpenNav={() => setNavOpen(true)}
              onOpenPalette={() => setPaletteOpen(true)}
            />

            {shell.restartRequired ? (
              <div className="border-b border-primary/30 bg-primary/10 px-4 py-2">
                <Alert className="border-0 bg-transparent p-0 shadow-none">
                  <AlertTitle className="text-xs font-semibold text-primary">
                    Restart required
                  </AlertTitle>
                  <AlertDescription className="mt-1 flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
                    <span className="truncate">
                      {shell.restartMsg || "configuration changed"}
                    </span>
                    <Button
                      asChild
                      size="xs"
                      className="bg-primary text-primary-foreground hover:bg-primary/90"
                    >
                      <NavLink to="/runtime">Open Runtime</NavLink>
                    </Button>
                  </AlertDescription>
                </Alert>
              </div>
            ) : null}

            <main className="mx-auto w-full max-w-7xl flex-1 overflow-auto p-4 md:p-6">
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/tools" element={<ToolsPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/health" element={<HealthPage />} />
                <Route path="/tasks" element={<TasksPage />} />
                <Route path="/inventory" element={<InventoryPage />} />
                <Route path="/observability" element={<ObservabilityPage />} />
                <Route path="/approvals" element={<ApprovalsPage />} />
                <Route
                  path="/servers"
                  element={isAdmin ? <ServersPage /> : <Navigate to="/" replace />}
                />
                <Route
                  path="/access"
                  element={isAdmin ? <AccessPage /> : <Navigate to="/" replace />}
                />
                <Route path="/users" element={<Navigate to="/access" replace />} />
                <Route
                  path="/secrets"
                  element={isAdmin ? <SecretsPage /> : <Navigate to="/" replace />}
                />
                <Route path="/config" element={<ConfigPage />} />
                <Route
                  path="/runtime"
                  element={isAdmin ? <RuntimePage /> : <Navigate to="/" replace />}
                />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </main>
          </div>

          <CommandPalette
            open={paletteOpen}
            onOpenChange={setPaletteOpen}
            isAdmin={isAdmin}
          />
        </div>
      </HostCatalogProvider>
    </ShellStatusContext.Provider>
  );
}

export default function App() {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-svh bg-background">
        <LoadingBlock label="Starting control plane…" />
      </div>
    );
  }
  if (!user) return <LoginPage />;
  return (
    <TooltipProvider delayDuration={200}>
      <PrivacyProvider>
        <Shell />
      </PrivacyProvider>
    </TooltipProvider>
  );
}
