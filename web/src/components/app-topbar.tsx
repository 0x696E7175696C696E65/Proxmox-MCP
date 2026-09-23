import { useLocation } from "react-router-dom";
import { Eye, EyeOff, Menu, Search } from "lucide-react";
import { useShellStatus } from "../shell-status";
import { usePrivacy } from "../privacy";
import { HostSwitcher } from "@/components/host-switcher";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const TITLES: Record<string, string> = {
  "/": "Overview",
  "/tools": "Tools",
  "/inventory": "Inventory",
  "/tasks": "Tasks",
  "/audit": "Audit",
  "/health": "Health",
  "/observability": "Observability",
  "/approvals": "Approvals",
  "/servers": "Servers",
  "/users": "Users",
  "/secrets": "Secrets",
  "/config": "Config",
  "/runtime": "Runtime",
};

export function AppTopBar({
  onOpenNav,
  onOpenPalette,
}: {
  onOpenNav: () => void;
  onOpenPalette: () => void;
}) {
  const { pathname } = useLocation();
  const status = useShellStatus();
  const { enabled: privacyOn, toggle: togglePrivacy } = usePrivacy();
  const title = TITLES[pathname] ?? "Control plane";
  const healthOk = ["ok", "ready"].includes(status.healthStatus.toLowerCase());

  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-border/80 bg-card/40 px-3 backdrop-blur md:px-4">
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="lg:hidden"
        onClick={onOpenNav}
        aria-label="Open navigation"
      >
        <Menu className="size-4" />
      </Button>

      <div className="min-w-0 flex-1">
        <div className="truncate text-[13px] font-semibold tracking-tight">{title}</div>
        <div className="hidden text-[10px] uppercase tracking-[0.12em] text-muted-foreground sm:block">
          Proxmox MCP · Control plane
        </div>
      </div>

      <HostSwitcher />

      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className={cn(
          "shrink-0 text-muted-foreground transition-colors duration-200",
          privacyOn && "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary",
        )}
        aria-pressed={privacyOn}
        aria-label={privacyOn ? "Show IPs and sensitive info" : "Hide IPs and sensitive info"}
        title={privacyOn ? "Privacy on — click to reveal" : "Hide IPs & sensitive info"}
        onClick={togglePrivacy}
      >
        {privacyOn ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
      </Button>

      <div className="hidden items-center gap-2 md:flex">
        <div className="flex items-center gap-1.5 rounded-md border border-border/70 bg-muted/20 px-2 py-1">
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Health</span>
          <StatusBadge status={healthOk ? "ok" : "error"} />
        </div>
        <div
          className={cn(
            "flex max-w-[140px] items-center gap-1.5 truncate rounded-md border border-border/70 bg-muted/20 px-2 py-1 font-mono text-[10px] text-muted-foreground",
            status.restartRequired && "border-primary/40 text-primary",
          )}
          title={status.runtimeMessage}
        >
          <span
            className={cn(
              "inline-block size-1.5 shrink-0 rounded-full",
              status.restartRequired
                ? "animate-pulse bg-primary shadow-[0_0_6px_currentColor]"
                : "bg-muted-foreground/50",
            )}
            aria-hidden
          />
          <span className="truncate">
            {status.restartRequired ? "restart pending" : status.runtimeMessage || "idle"}
          </span>
        </div>
        {status.pendingApprovals > 0 ? (
          <div className="rounded-md border border-primary/35 bg-primary/10 px-2 py-1 font-mono text-[10px] text-primary">
            {status.pendingApprovals} pending
          </div>
        ) : null}
      </div>

      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-8 gap-2 text-[12px] text-muted-foreground"
        onClick={onOpenPalette}
      >
        <Search className="size-3.5" />
        <span className="hidden sm:inline">Search</span>
        <kbd className="hidden rounded border border-border bg-muted/50 px-1 py-0 font-mono text-[10px] sm:inline">
          ⌘K
        </kbd>
      </Button>
    </header>
  );
}
