import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border/80 bg-muted/20 px-6 py-10 text-center",
        className,
      )}
    >
      <div className="flex size-9 items-center justify-center rounded-md bg-primary/10 ring-1 ring-primary/25">
        <Icon className="size-4 text-primary" />
      </div>
      <div className="space-y-1">
        <p className="text-[13px] font-medium text-foreground">{title}</p>
        <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">{description}</p>
      </div>
      {action ? <div className="mt-1">{action}</div> : null}
    </div>
  );
}
