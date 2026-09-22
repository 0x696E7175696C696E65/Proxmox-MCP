import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const RISK_CLASS: Record<string, string> = {
  low: "border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[oklch(0.78_0.14_155)]",
  medium: "border-transparent bg-primary/15 text-primary",
  high: "border-transparent bg-[oklch(0.75_0.14_70/0.18)] text-[oklch(0.82_0.14_70)]",
  critical: "border-transparent bg-destructive/15 text-destructive",
};

export function RiskBadge({ risk, className }: { risk: string; className?: string }) {
  const key = risk.toLowerCase();
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-sm px-1.5 py-0 font-mono text-[10px] uppercase tracking-wide",
        RISK_CLASS[key] ?? "text-muted-foreground",
        className,
      )}
    >
      {risk}
    </Badge>
  );
}
