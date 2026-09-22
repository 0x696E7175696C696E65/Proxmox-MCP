import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-border/70 pb-3",
        className,
      )}
    >
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-tight text-foreground">{title}</h1>
        {description ? (
          <p className="mt-1 max-w-2xl text-[13px] leading-snug text-muted-foreground">
            {description}
          </p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
