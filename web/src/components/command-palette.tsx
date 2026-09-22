import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  FileKey2,
  Gauge,
  HardDrive,
  HeartPulse,
  LayoutDashboard,
  Search,
  Settings2,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { cn } from "@/lib/utils";

const BASE_COMMANDS = [
  { to: "/", label: "Overview", hint: "Gateway status", icon: LayoutDashboard },
  { to: "/tools", label: "Tools", hint: "Browse and invoke", icon: Wrench },
  { to: "/audit", label: "Audit", hint: "Live event stream", icon: Activity },
  { to: "/health", label: "Health", hint: "Dependencies & doctor", icon: HeartPulse },
  { to: "/approvals", label: "Approvals", hint: "Dangerous ops queue", icon: ShieldCheck },
  { to: "/config", label: "Config", hint: "Hot-apply settings", icon: Settings2 },
] as const;

const ADMIN_COMMANDS = [
  { to: "/servers", label: "Servers", hint: "Managed Proxmox hosts", icon: HardDrive },
  { to: "/secrets", label: "Secrets", hint: "API & service tokens", icon: FileKey2 },
  { to: "/runtime", label: "Runtime", hint: "Restart & apply state", icon: Gauge },
] as const;

export function CommandPalette({
  open,
  onOpenChange,
  isAdmin,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isAdmin: boolean;
}) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = useMemo(
    () => [...BASE_COMMANDS, ...(isAdmin ? ADMIN_COMMANDS : [])],
    [isAdmin],
  );

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(needle) ||
        c.hint.toLowerCase().includes(needle) ||
        c.to.toLowerCase().includes(needle),
    );
  }, [q, commands]);

  useEffect(() => {
    if (!open) return;
    setQ("");
    setActive(0);
    const id = window.setTimeout(() => inputRef.current?.focus(), 20);
    return () => window.clearTimeout(id);
  }, [open]);

  useEffect(() => {
    setActive(0);
  }, [q]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  if (!open) return null;

  function go(to: string) {
    onOpenChange(false);
    navigate(to);
  }

  return (
    <div className="fixed inset-0 z-[100]">
      <button
        type="button"
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
        aria-label="Close command palette"
        onClick={() => onOpenChange(false)}
      />
      <div className="relative mx-auto mt-[12vh] w-full max-w-lg px-4">
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Command palette"
          className="overflow-hidden rounded-lg border border-border bg-card shadow-2xl ring-1 ring-white/5"
        >
          <div className="flex items-center gap-2 border-b border-border px-3">
            <Search className="size-4 shrink-0 text-muted-foreground" />
            <input
              ref={inputRef}
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Jump to page…"
              className="h-11 w-full bg-transparent text-[13px] outline-none placeholder:text-muted-foreground"
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  e.preventDefault();
                  onOpenChange(false);
                } else if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActive((i) => Math.min(i + 1, Math.max(filtered.length - 1, 0)));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActive((i) => Math.max(i - 1, 0));
                } else if (e.key === "Enter" && filtered[active]) {
                  e.preventDefault();
                  go(filtered[active].to);
                }
              }}
            />
            <kbd className="hidden rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:inline">
              esc
            </kbd>
          </div>
          <ul className="max-h-[320px] overflow-y-auto p-1.5">
            {filtered.length === 0 ? (
              <li className="px-3 py-6 text-center text-xs text-muted-foreground">No matches</li>
            ) : (
              filtered.map((cmd, i) => (
                <li key={cmd.to}>
                  <button
                    type="button"
                    className={cn(
                      "flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-left transition-colors",
                      i === active ? "bg-primary/15 text-foreground" : "hover:bg-muted/40",
                    )}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => go(cmd.to)}
                  >
                    <cmd.icon
                      className={cn(
                        "size-4 shrink-0",
                        i === active ? "text-primary" : "text-muted-foreground",
                      )}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block text-[13px] font-medium">{cmd.label}</span>
                      <span className="block text-[11px] text-muted-foreground">{cmd.hint}</span>
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground">{cmd.to}</span>
                  </button>
                </li>
              ))
            )}
          </ul>
          <div className="border-t border-border px-3 py-1.5 text-[10px] text-muted-foreground">
            ↑↓ navigate · Enter open · Esc close
          </div>
        </div>
      </div>
    </div>
  );
}
