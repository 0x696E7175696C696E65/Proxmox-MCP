import { useState, type ReactNode } from "react";
import { Check, ChevronDown, ChevronRight, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function formatValue(value: unknown): ReactNode {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground/70">—</span>;
  }
  if (typeof value === "boolean") {
    return (
      <span className={value ? "text-[oklch(0.78_0.14_155)]" : "text-muted-foreground"}>
        {String(value)}
      </span>
    );
  }
  if (typeof value === "number") {
    return <span className="tabular-nums">{value}</span>;
  }
  if (typeof value === "string") {
    if (!value) return <span className="text-muted-foreground/70">—</span>;
    return <span className="break-all">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-muted-foreground/70">[]</span>;
    return (
      <span className="font-mono text-[11px] text-muted-foreground">
        [{value.length} item{value.length === 1 ? "" : "s"}]
      </span>
    );
  }
  if (typeof value === "object") {
    const keys = Object.keys(value as object);
    if (keys.length === 0) return <span className="text-muted-foreground/70">{"{}"}</span>;
    return (
      <span className="font-mono text-[11px] text-muted-foreground">
        {"{"}
        {keys.length} key{keys.length === 1 ? "" : "s"}
        {"}"}
      </span>
    );
  }
  return String(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEmptyValue(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (value === "") return true;
  if (Array.isArray(value) && value.length === 0) return true;
  if (isPlainObject(value) && Object.keys(value).length === 0) return true;
  return false;
}

function KvRows({
  data,
  depth = 0,
  hideEmpty = false,
}: {
  data: Record<string, unknown>;
  depth?: number;
  hideEmpty?: boolean;
}) {
  const entries = Object.entries(data).filter(([, value]) =>
    hideEmpty ? !isEmptyValue(value) : true,
  );
  if (entries.length === 0) {
    return (
      <div className="px-3 py-2.5 text-xs text-muted-foreground">
        {hideEmpty ? "No meaningful fields" : "No fields"}
      </div>
    );
  }

  return (
    <div className={cn(depth > 0 && "ml-2 border-l border-border/60")}>
      {entries.map(([key, value]) => {
        const nested = isPlainObject(value) && Object.keys(value).length > 0;
        const list = Array.isArray(value) && value.length > 0 && value.every(isPlainObject);

        if (nested) {
          return (
            <details key={key} className="group border-b border-border/50 last:border-0" open={depth === 0}>
              <summary className="flex cursor-pointer list-none items-center gap-1.5 px-3 py-2 text-[12px] hover:bg-muted/30 [&::-webkit-details-marker]:hidden">
                <ChevronRight className="size-3 shrink-0 text-muted-foreground group-open:hidden" />
                <ChevronDown className="hidden size-3 shrink-0 text-muted-foreground group-open:block" />
                <span className="font-mono text-[11px] text-muted-foreground">{key}</span>
              </summary>
              <KvRows data={value} depth={depth + 1} hideEmpty={hideEmpty} />
            </details>
          );
        }

        if (list) {
          return (
            <details key={key} className="group border-b border-border/50 last:border-0">
              <summary className="flex cursor-pointer list-none items-center gap-1.5 px-3 py-2 text-[12px] hover:bg-muted/30 [&::-webkit-details-marker]:hidden">
                <ChevronRight className="size-3 shrink-0 text-muted-foreground group-open:hidden" />
                <ChevronDown className="hidden size-3 shrink-0 text-muted-foreground group-open:block" />
                <span className="font-mono text-[11px] text-muted-foreground">{key}</span>
                <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                  {value.length}
                </span>
              </summary>
              <div className="ml-2 space-y-1 border-l border-border/60 py-1 pl-2">
                {value.map((item, i) => (
                  <div key={i} className="overflow-hidden rounded-md border border-border/50">
                    <div className="border-b border-border/40 bg-muted/20 px-2 py-1 font-mono text-[10px] text-muted-foreground">
                      [{i}]
                    </div>
                    <KvRows
                      data={item as Record<string, unknown>}
                      depth={depth + 1}
                      hideEmpty={hideEmpty}
                    />
                  </div>
                ))}
              </div>
            </details>
          );
        }

        return (
          <div
            key={key}
            className="grid grid-cols-[minmax(0,34%)_1fr] items-start gap-3 border-b border-border/50 px-3 py-2.5 last:border-0"
          >
            <div className="truncate pt-0.5 font-mono text-[11px] text-muted-foreground" title={key}>
              {key}
            </div>
            <div className="min-w-0 font-mono text-[12px] leading-snug text-foreground">
              {formatValue(value)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function KvPanel({
  title,
  data,
  className,
  defaultHideEmpty = true,
}: {
  title: string;
  data: Record<string, unknown> | null | undefined;
  className?: string;
  defaultHideEmpty?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const [hideEmpty, setHideEmpty] = useState(defaultHideEmpty);
  const payload = data ?? {};

  async function copyJson() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className={cn("overflow-hidden rounded-md border border-border", className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border/70 bg-muted/20 px-3 py-1.5">
        <h4 className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          {title}
        </h4>
        <div className="flex items-center gap-0.5">
          <Button
            type="button"
            variant="ghost"
            size="xs"
            className="h-6 px-1.5 text-[10px] text-muted-foreground"
            onClick={() => setHideEmpty((v) => !v)}
          >
            {hideEmpty ? "Show empty" : "Hide empty"}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="xs"
            className="h-6 gap-1 px-1.5 text-[10px] text-muted-foreground"
            onClick={() => void copyJson()}
          >
            {copied ? (
              <Check className="size-3 text-[oklch(0.78_0.14_155)]" />
            ) : (
              <Copy className="size-3" />
            )}
            {copied ? "Copied" : "JSON"}
          </Button>
        </div>
      </div>
      <KvRows data={payload} hideEmpty={hideEmpty} />
    </div>
  );
}

/** Flatten JSON Schema properties into a readable parameter list. */
export function SchemaProperties({
  schema,
}: {
  schema: Record<string, unknown> | null;
}) {
  if (!schema) return null;
  const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = new Set(
    Array.isArray(schema.required) ? (schema.required as string[]) : [],
  );
  const keys = Object.keys(properties);

  if (keys.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-border/70 px-3 py-4 text-center text-xs text-muted-foreground">
        No parameters defined
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-md border border-border">
      <div className="border-b border-border/70 bg-muted/20 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
        Parameters · {keys.length}
      </div>
      <div>
        {keys.map((name) => {
          const prop = properties[name] ?? {};
          const type = String(prop.type ?? "any");
          const desc = typeof prop.description === "string" ? prop.description : "";
          return (
            <div key={name} className="border-b border-border/50 px-3 py-2 last:border-0">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-[12px] text-foreground">{name}</span>
                <span className="rounded-sm bg-muted/50 px-1 py-0 font-mono text-[10px] text-muted-foreground">
                  {type}
                </span>
                {required.has(name) ? (
                  <span className="font-mono text-[10px] text-primary">required</span>
                ) : (
                  <span className="font-mono text-[10px] text-muted-foreground">optional</span>
                )}
              </div>
              {desc ? (
                <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">{desc}</p>
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
