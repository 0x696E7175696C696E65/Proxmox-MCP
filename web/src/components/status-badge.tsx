import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_CLASS: Record<string, string> = {
  success: "border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[oklch(0.78_0.14_155)]",
  error: "border-transparent bg-destructive/15 text-destructive",
  denied: "border-transparent bg-muted text-muted-foreground",
  started: "border-transparent bg-primary/15 text-primary",
  ok: "border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[oklch(0.78_0.14_155)]",
  ready: "border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[oklch(0.78_0.14_155)]",
  idle: "border-transparent bg-muted/40 text-muted-foreground",
  connecting: "border-transparent bg-primary/15 text-primary",
  syncing: "border-transparent bg-primary/15 text-primary",
};

const LIVE_STATUSES = new Set(["ok", "ready", "success", "started", "connecting", "syncing"]);

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const key = status.toLowerCase();
  const live = LIVE_STATUSES.has(key);
  const errored = key === "error" || key === "denied";

  return (
    <Badge
      variant="outline"
      className={cn(
        "inline-flex items-center gap-1 rounded-sm px-1.5 py-0 font-mono text-[10px] uppercase tracking-wide",
        STATUS_CLASS[key] ?? "text-muted-foreground",
        className,
      )}
    >
      <span
        className={cn(
          "inline-block size-1.5 shrink-0 rounded-full",
          live && "bg-current shadow-[0_0_6px_currentColor]",
          live && "animate-pulse",
          errored && "bg-current",
          !live && !errored && "bg-current/50",
        )}
        aria-hidden
      />
      {status}
    </Badge>
  );
}
