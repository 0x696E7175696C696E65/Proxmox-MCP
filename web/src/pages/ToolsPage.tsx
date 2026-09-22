import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { Check, Copy, Lock, Play, Search, Wrench, X } from "lucide-react";
import { AdminApi, type ToolSummary } from "../api";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { useMediaQuery } from "../hooks/useMediaQuery";
import { EmptyState } from "@/components/empty-state";
import { KvPanel, SchemaProperties } from "@/components/kv-panel";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { RiskBadge } from "@/components/risk-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

const RISK_FILTERS = ["all", "low", "medium", "high", "critical"] as const;

function shortDescription(text: string): string {
  return text
    .replace(/^(DESTRUCTIVE|GUARDED|READ-ONLY)\s+/i, "")
    .replace(/^(critical|high|medium|low)[-\s]?risk[.:]?\s*/i, "")
    .trim();
}

function ToolDetail({
  selected,
  schema,
  paramsJson,
  setParamsJson,
  resourceType,
  setResourceType,
  resourceId,
  setResourceId,
  result,
  error,
  busy,
  copied,
  onCopy,
  onInvoke,
  onClose,
}: {
  selected: ToolSummary;
  schema: Record<string, unknown> | null;
  paramsJson: string;
  setParamsJson: (v: string) => void;
  resourceType: string;
  setResourceType: (v: string) => void;
  resourceId: string;
  setResourceId: (v: string) => void;
  result: Record<string, unknown> | null;
  error: string | null;
  busy: boolean;
  copied: boolean;
  onCopy: () => void;
  onInvoke: () => void;
  onClose?: () => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="truncate font-mono text-[14px] font-semibold">{selected.name}</h2>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {shortDescription(selected.description)}
          </p>
        </div>
        <div className="flex shrink-0 gap-1">
          <Button type="button" size="xs" variant="ghost" onClick={onCopy}>
            {copied ? (
              <Check className="size-3.5 text-[oklch(0.78_0.14_155)]" />
            ) : (
              <Copy className="size-3.5" />
            )}
            {copied ? "Copied" : "Copy"}
          </Button>
          {onClose ? (
            <Button type="button" size="xs" variant="ghost" onClick={onClose} aria-label="Close">
              <X className="size-3.5" />
            </Button>
          ) : null}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        <RiskBadge risk={selected.risk} />
        <Badge variant="outline" className="rounded-sm font-mono text-[10px]">
          {selected.connector}
        </Badge>
        <Badge variant="outline" className="rounded-sm text-[10px]">
          {selected.category}
        </Badge>
        {!selected.invokable ? (
          <Badge
            variant="outline"
            className="rounded-sm border-destructive/30 bg-destructive/10 text-[10px] text-destructive"
          >
            UI invoke blocked
          </Badge>
        ) : (
          <Badge
            variant="outline"
            className="rounded-sm border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[10px] text-[oklch(0.78_0.14_155)]"
          >
            Invokable
          </Badge>
        )}
      </div>

      {selected.invokable ? (
        <Card className="shadow-none">
          <CardContent className="space-y-2.5 p-3">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Invoke
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  resource_type
                </Label>
                <Input
                  className="h-7 font-mono text-xs"
                  value={resourceType}
                  onChange={(e) => setResourceType(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  resource_id
                </Label>
                <Input
                  className="h-7 font-mono text-xs"
                  value={resourceId}
                  onChange={(e) => setResourceId(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-[10px] uppercase tracking-wide text-muted-foreground">
                parameters JSON
              </Label>
              <textarea
                className="min-h-[90px] w-full rounded-md border border-input bg-transparent p-2 font-mono text-[11px]"
                value={paramsJson}
                onChange={(e) => setParamsJson(e.target.value)}
              />
            </div>
            <Button size="sm" disabled={busy} onClick={onInvoke}>
              {busy ? "Running…" : "Invoke"}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Alert>
          <AlertDescription className="text-xs">
            High/critical tools cannot be invoked here.{" "}
            <NavLink to="/approvals" className="text-primary underline-offset-2 hover:underline">
              Use Approvals
            </NavLink>{" "}
            for gated ops.
          </AlertDescription>
        </Alert>
      )}

      {error ? <p className="text-xs text-destructive">{error}</p> : null}
      <SchemaProperties schema={schema} />
      {result ? <KvPanel title="Result" data={result} /> : null}
    </div>
  );
}

export function ToolsPage() {
  const split = useMediaQuery("(min-width: 1280px)");
  const [tools, setTools] = useState<ToolSummary[]>([]);
  const [q, setQ] = useState("");
  const [risk, setRisk] = useState<string>("all");
  const [invokableOnly, setInvokableOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ToolSummary | null>(null);
  const [schema, setSchema] = useState<Record<string, unknown> | null>(null);
  const [paramsJson, setParamsJson] = useState("{}");
  const [resourceType, setResourceType] = useState("cluster");
  const [resourceId, setResourceId] = useState("homelab");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const debouncedQ = useDebouncedValue(q, 250);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (debouncedQ.trim()) params.set("q", debouncedQ.trim());
    if (risk !== "all") params.set("risk", risk);
    void AdminApi.tools(params)
      .then((res) => setTools(res.tools))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [debouncedQ, risk]);

  const visible = useMemo(
    () => (invokableOnly ? tools.filter((t) => t.invokable) : tools),
    [tools, invokableOnly],
  );
  const invokableCount = useMemo(() => tools.filter((t) => t.invokable).length, [tools]);

  async function openTool(tool: ToolSummary) {
    setSelected(tool);
    setResult(null);
    setError(null);
    setParamsJson("{}");
    setSchema(null);
    setCopied(false);
    try {
      const detail = await AdminApi.tool(tool.name);
      setSchema(detail.parameters_schema);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load tool");
    }
  }

  async function copyName() {
    if (!selected) return;
    try {
      await navigator.clipboard.writeText(selected.name);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      /* ignore */
    }
  }

  async function invoke() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const parameters = JSON.parse(paramsJson) as Record<string, unknown>;
      const res = await AdminApi.invokeTool(selected.name, {
        target: { resource_type: resourceType, resource_id: resourceId },
        parameters,
      });
      const payload = res.result;
      setResult(
        payload && typeof payload === "object" && !Array.isArray(payload)
          ? (payload as Record<string, unknown>)
          : { value: payload },
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invoke failed");
    } finally {
      setBusy(false);
    }
  }

  const detailProps = selected
    ? {
        selected,
        schema,
        paramsJson,
        setParamsJson,
        resourceType,
        setResourceType,
        resourceId,
        setResourceId,
        result,
        error,
        busy,
        copied,
        onCopy: () => void copyName(),
        onInvoke: () => void invoke(),
      }
    : null;

  const list = (
    <div className="min-w-0 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="h-8 w-[220px] pl-8"
            placeholder="Search tools…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div className="flex flex-wrap gap-1">
          {RISK_FILTERS.map((level) => (
            <Button
              key={level}
              type="button"
              size="xs"
              variant={risk === level ? "default" : "outline"}
              className={cn(
                "h-7 px-2 font-mono text-[10px] uppercase",
                risk === level && "bg-primary text-primary-foreground",
              )}
              onClick={() => setRisk(level)}
            >
              {level === "all" ? "all" : level}
            </Button>
          ))}
        </div>
        <Button
          type="button"
          size="xs"
          variant={invokableOnly ? "default" : "outline"}
          className="h-7"
          onClick={() => setInvokableOnly((v) => !v)}
        >
          Invokable only
        </Button>
      </div>

      {error && !selected ? <p className="text-sm text-destructive">{error}</p> : null}

      {loading && tools.length === 0 ? (
        <LoadingBlock label="Loading tools…" />
      ) : visible.length === 0 ? (
        <EmptyState
          icon={Wrench}
          title="No tools match"
          description="Try clearing filters — registered MCP tools will appear here."
          action={
            q || risk !== "all" || invokableOnly ? (
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setQ("");
                  setRisk("all");
                  setInvokableOnly(false);
                }}
              >
                Clear filters
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <Table className="table-fixed">
            <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-8 w-[55%] px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Name
                </TableHead>
                <TableHead className="h-8 w-[15%] px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Risk
                </TableHead>
                <TableHead className="h-8 w-[30%] px-3 text-[10px] font-semibold uppercase tracking-[0.12em]">
                  Category
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((tool) => (
                <TableRow
                  key={tool.name}
                  className={cn(
                    "cursor-pointer",
                    selected?.name === tool.name && "bg-primary/10",
                  )}
                  onClick={() => void openTool(tool)}
                >
                  <TableCell className="max-w-0 whitespace-normal px-3 py-2 align-top">
                    <div className="flex items-start gap-2">
                      <div className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md bg-muted/40 ring-1 ring-border/60">
                        {tool.invokable ? (
                          <Play className="size-3 text-primary" />
                        ) : (
                          <Lock className="size-3 text-muted-foreground" />
                        )}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-mono text-[12px] font-medium">
                          {tool.name}
                        </div>
                        <div className="mt-0.5 line-clamp-1 text-[11px] text-muted-foreground">
                          {shortDescription(tool.description)}
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="px-3 py-2 align-top">
                    <RiskBadge risk={tool.risk} />
                  </TableCell>
                  <TableCell className="truncate px-3 py-2 align-top text-[12px] text-muted-foreground">
                    {tool.category}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-3">
      <PageHeader
        title="Tools"
        description="Browse registered MCP tools and invoke low/medium risk reads."
        actions={
          <Badge variant="outline" className="h-7 font-mono text-[10px]">
            {invokableCount}/{tools.length} invokable
          </Badge>
        }
      />

      {split ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
          {list}
          <div className="min-h-[420px] rounded-md border border-border bg-card/30 p-4">
            {detailProps ? (
              <ToolDetail {...detailProps} onClose={() => setSelected(null)} />
            ) : (
              <EmptyState
                icon={Wrench}
                title="Select a tool"
                description="Pick a row to inspect schema and invoke low/medium risk tools."
                className="border-0 bg-transparent py-16"
              />
            )}
          </div>
        </div>
      ) : (
        <>
          {list}
          <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
            <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
              {detailProps ? (
                <>
                  <SheetHeader className="sr-only">
                    <SheetTitle>{detailProps.selected.name}</SheetTitle>
                    <SheetDescription>Tool detail</SheetDescription>
                  </SheetHeader>
                  <div className="mt-2 px-1">
                    <ToolDetail {...detailProps} />
                  </div>
                </>
              ) : null}
            </SheetContent>
          </Sheet>
        </>
      )}
    </div>
  );
}
