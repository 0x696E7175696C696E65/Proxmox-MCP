import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function FormSection({
  title,
  description,
  children,
  className,
  actions,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <Card className={cn("shadow-none", className)}>
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0 px-4 py-3">
        <div className="min-w-0 space-y-0.5">
          <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            {title}
          </CardTitle>
          {description ? (
            <p className="text-xs leading-snug text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {actions}
      </CardHeader>
      <CardContent className="space-y-3 px-4 pb-4 pt-0">{children}</CardContent>
    </Card>
  );
}

export function FieldLabel({
  htmlFor,
  children,
  hint,
}: {
  htmlFor?: string;
  children: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <label
      htmlFor={htmlFor}
      className="flex flex-wrap items-baseline gap-x-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground"
    >
      <span>{children}</span>
      {hint ? (
        <span className="font-mono text-[10px] font-normal normal-case tracking-normal text-muted-foreground/80">
          {hint}
        </span>
      ) : null}
    </label>
  );
}
