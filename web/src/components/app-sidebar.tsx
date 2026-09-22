import { NavLink } from "react-router-dom";
import type { LucideIcon } from "lucide-react";
import { LogOut, Shield, X } from "lucide-react";
import { useShellStatus } from "../shell-status";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type NavItem = {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  badge?: string | number | null;
};

export type NavGroup = {
  label: string;
  items: readonly NavItem[];
};

function SidebarPanel({
  groups,
  username,
  onLogout,
  onNavigate,
  onClose,
}: {
  groups: readonly NavGroup[];
  username?: string;
  onLogout: () => void;
  onNavigate?: () => void;
  onClose?: () => void;
}) {
  const status = useShellStatus();
  const healthOk = ["ok", "ready"].includes(status.healthStatus.toLowerCase());

  return (
    <aside className="flex h-full w-[232px] shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
      <div className="flex items-center gap-2.5 border-b border-sidebar-border px-3.5 py-3.5">
        <div className="flex size-8 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/35">
          <Shield className="size-4 text-primary" />
        </div>
        <div className="min-w-0 flex-1 leading-tight">
          <div className="truncate text-[13px] font-semibold tracking-tight text-foreground">
            Proxmox MCP
          </div>
          <div className="truncate text-[11px] text-muted-foreground">Control plane</div>
        </div>
        {onClose ? (
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="lg:hidden"
            onClick={onClose}
            aria-label="Close navigation"
          >
            <X className="size-4" />
          </Button>
        ) : null}
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto px-2.5 py-3">
        {groups.map((group) => (
          <div key={group.label}>
            <div className="mb-1.5 px-2.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
              {group.label}
            </div>
            <nav className="flex flex-col gap-0.5" aria-label={group.label}>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "group relative flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium transition-colors",
                      "text-muted-foreground hover:bg-white/[0.05] hover:text-foreground",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60",
                      isActive &&
                        "bg-primary/18 text-foreground ring-1 ring-primary/30 shadow-[inset_3px_0_0_0_var(--primary)]",
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <item.icon
                        className={cn(
                          "size-4 shrink-0 transition-colors",
                          isActive
                            ? "text-primary"
                            : "text-muted-foreground group-hover:text-foreground",
                        )}
                      />
                      <span className="min-w-0 flex-1 truncate">{item.label}</span>
                      {item.badge != null && item.badge !== "" && Number(item.badge) !== 0 ? (
                        <span
                          className={cn(
                            "rounded-sm px-1.5 py-0 font-mono text-[10px] tabular-nums",
                            isActive
                              ? "bg-primary/25 text-primary"
                              : "bg-white/[0.06] text-muted-foreground",
                          )}
                        >
                          {item.badge}
                        </span>
                      ) : null}
                    </>
                  )}
                </NavLink>
              ))}
            </nav>
          </div>
        ))}
      </div>

      <div className="space-y-2 border-t border-sidebar-border p-2.5">
        <div className="flex items-center justify-between gap-2 rounded-md bg-white/[0.04] px-2.5 py-2 ring-1 ring-white/[0.07]">
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Gateway
            </div>
            <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
              {status.runtimeMessage || "idle"}
            </div>
          </div>
          <StatusBadge status={healthOk ? "ok" : "error"} />
        </div>
        <div className="rounded-md bg-white/[0.04] px-2.5 py-2 ring-1 ring-white/[0.07]">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Signed in
          </div>
          <div className="mt-0.5 truncate font-mono text-[12px] text-foreground">
            {username ?? "—"}
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-full justify-start gap-2 text-[12.5px] text-muted-foreground hover:bg-white/[0.06] hover:text-foreground"
          onClick={onLogout}
        >
          <LogOut className="size-3.5" />
          Sign out
        </Button>
      </div>
    </aside>
  );
}

export function AppSidebar({
  groups,
  username,
  onLogout,
  mobileOpen,
  onMobileClose,
}: {
  groups: readonly NavGroup[];
  username?: string;
  onLogout: () => void;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}) {
  return (
    <>
      <div className="hidden h-svh lg:block">
        <SidebarPanel groups={groups} username={username} onLogout={onLogout} />
      </div>
      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-black/55"
            aria-label="Close navigation overlay"
            onClick={onMobileClose}
          />
          <div className="absolute inset-y-0 left-0 shadow-2xl">
            <SidebarPanel
              groups={groups}
              username={username}
              onLogout={onLogout}
              onNavigate={onMobileClose}
              onClose={onMobileClose}
            />
          </div>
        </div>
      ) : null}
    </>
  );
}
