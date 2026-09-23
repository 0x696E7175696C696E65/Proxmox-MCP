import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, Shield } from "lucide-react";
import { AdminApi } from "../api";
import { EmptyState } from "@/components/empty-state";
import { FieldLabel } from "@/components/form-section";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

type CapRole = {
  role_id: string;
  name: string;
  description: string;
  granted_tools: string[];
  denied_tools: string[];
  system: boolean;
  grant_count: number;
  version: number;
};

type AclTool = {
  name: string;
  description: string;
  risk: string;
  connector: string;
  permission: string;
};

function riskBadgeClass(risk: string): string {
  const r = risk.toLowerCase();
  if (r === "critical" || r === "high") {
    return "border-destructive/40 text-destructive";
  }
  if (r === "medium") {
    return "border-amber-600/40 text-amber-700 dark:text-amber-400";
  }
  return "border-border text-muted-foreground";
}

export function AccessPage() {
  const [tab, setTab] = useState<"roles" | "users">("roles");
  const [roles, setRoles] = useState<CapRole[]>([]);
  const [tools, setTools] = useState<AclTool[]>([]);
  const [groups, setGroups] = useState<Record<string, string[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draftName, setDraftName] = useState("");
  const [draftDescription, setDraftDescription] = useState("");
  const [granted, setGranted] = useState<Set<string>>(new Set());
  const [denied, setDenied] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [stepUp, setStepUp] = useState("");
  const [busy, setBusy] = useState(false);
  const [allowStar, setAllowStar] = useState(false);
  const [previewTool, setPreviewTool] = useState("");
  const [previewResult, setPreviewResult] = useState<string | null>(null);
  const [groupFilter, setGroupFilter] = useState<string>("all");
  const [users, setUsers] = useState<
    Array<{ user_id: string; username: string; role: string; capability_role_id?: string | null }>
  >([]);

  const refresh = useCallback(async () => {
    const [roleData, toolData, userData] = await Promise.all([
      AdminApi.accessRoles(),
      AdminApi.accessTools(),
      AdminApi.users(),
    ]);
    setRoles(roleData.roles as CapRole[]);
    setTools(toolData.tools as AclTool[]);
    setGroups((toolData.groups as Record<string, string[]>) ?? {});
    setUsers(userData.users ?? []);
  }, []);

  useEffect(() => {
    void refresh()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [refresh]);

  const selected = useMemo(
    () => roles.find((r) => r.role_id === selectedId) ?? null,
    [roles, selectedId],
  );

  function openRole(role: CapRole) {
    setSelectedId(role.role_id);
    setDraftName(role.name);
    setDraftDescription(role.description);
    setGranted(new Set(role.granted_tools));
    setDenied(new Set(role.denied_tools));
    setAllowStar(role.granted_tools.includes("*"));
    setStepUp("");
    setError(null);
    setMessage(null);
    setPreviewResult(null);
  }

  function startCreate() {
    setSelectedId(null);
    setDraftName("");
    setDraftDescription("");
    setGranted(new Set());
    setDenied(new Set());
    setAllowStar(false);
    setStepUp("");
    setMessage(null);
    setPreviewResult(null);
  }

  function toggleGrant(name: string) {
    setGranted((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function saveRole() {
    if (!stepUp.trim()) {
      setError("Confirm admin password (step-up)");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (selectedId && selected && !selected.system) {
        await AdminApi.updateAccessRole(selectedId, {
          name: draftName,
          description: draftDescription,
          granted_tools: allowStar ? ["*", ...[...granted].filter((t) => t !== "*")] : [...granted],
          denied_tools: [...denied],
          allow_star: allowStar,
          password: stepUp,
        });
        setMessage(`Updated role ${draftName}`);
      } else {
        const created = await AdminApi.createAccessRole({
          name: draftName,
          description: draftDescription,
          granted_tools: allowStar ? ["*", ...[...granted].filter((t) => t !== "*")] : [...granted],
          denied_tools: [...denied],
          allow_star: allowStar,
          password: stepUp,
        });
        setMessage(`Created role ${draftName}`);
        setSelectedId((created.role as CapRole).role_id);
      }
      setStepUp("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function assignUserRole(userId: string, capabilityRoleId: string) {
    const password = window.prompt("Confirm your admin password (step-up)") ?? "";
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      await AdminApi.updateUser(userId, {
        capability_role_id: capabilityRoleId || null,
        password,
      });
      setMessage("User capability role updated");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  const filteredTools = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const inGroup =
      groupFilter === "all"
        ? null
        : new Set(groups[groupFilter] ?? []);
    return tools.filter((t) => {
      if (inGroup && !inGroup.has(t.name)) return false;
      if (!q) return true;
      return (
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.permission.toLowerCase().includes(q)
      );
    });
  }, [tools, filter, groupFilter, groups]);

  const grantedCount = allowStar ? tools.length : granted.size;

  if (loading) return <LoadingBlock label="Loading access control…" />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Access"
        description="Capability roles with per-tool allow/deny. Deny wins. Server-enforced — UI hide is not auth."
        actions={
          <div className="inline-flex rounded-md border border-border p-0.5">
            <Button
              size="sm"
              variant={tab === "roles" ? "secondary" : "ghost"}
              className="rounded-sm"
              onClick={() => setTab("roles")}
            >
              Roles
            </Button>
            <Button
              size="sm"
              variant={tab === "users" ? "secondary" : "ghost"}
              className="rounded-sm"
              onClick={() => setTab("users")}
            >
              Users
            </Button>
          </div>
        }
      />

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {message ? (
        <Alert>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
      ) : null}

      {tab === "users" ? (
        <Card className="shadow-none">
          <CardHeader className="border-b border-border/60 px-4 py-3">
            <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              User capability bindings
            </CardTitle>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="h-8 px-4 text-[10px] uppercase">User</TableHead>
                  <TableHead className="h-8 px-4 text-[10px] uppercase">Console role</TableHead>
                  <TableHead className="h-8 px-4 text-[10px] uppercase">Capability role</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.user_id}>
                    <TableCell className="px-4 py-2.5 font-medium">{u.username}</TableCell>
                    <TableCell className="px-4 py-2.5">
                      <Badge variant="outline">{u.role}</Badge>
                    </TableCell>
                    <TableCell className="px-4 py-2.5">
                      <select
                        className="h-8 w-full max-w-xs rounded-md border border-input bg-background px-2 text-xs"
                        value={u.capability_role_id ?? ""}
                        disabled={busy}
                        onChange={(e) => void assignUserRole(u.user_id, e.target.value)}
                      >
                        <option value="">System default ({u.role})</option>
                        {roles.map((r) => (
                          <option key={r.role_id} value={r.role_id}>
                            {r.name} ({r.grant_count} tools)
                          </option>
                        ))}
                      </select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
          <Card className="h-fit shadow-none">
            <CardHeader className="flex flex-row items-center justify-between border-b border-border/60 px-3 py-2.5">
              <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Roles
              </CardTitle>
              <Button size="xs" variant="outline" onClick={startCreate}>
                New
              </Button>
            </CardHeader>
            <CardContent className="space-y-0.5 px-1.5 py-2">
              {roles.length === 0 ? (
                <EmptyState
                  icon={Shield}
                  title="No roles"
                  description="System roles seed on first load."
                />
              ) : (
                roles.map((role) => (
                  <button
                    key={role.role_id}
                    type="button"
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-[13px] transition-colors",
                      selectedId === role.role_id
                        ? "bg-primary/15 text-foreground ring-1 ring-primary/35"
                        : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
                    )}
                    onClick={() => openRole(role)}
                  >
                    <span className="min-w-0 flex-1 truncate font-medium">{role.name}</span>
                    {role.system ? (
                      <Badge variant="outline" className="shrink-0 px-1.5 py-0 text-[9px] uppercase">
                        system
                      </Badge>
                    ) : (
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                        {role.grant_count}
                      </span>
                    )}
                  </button>
                ))
              )}
            </CardContent>
          </Card>

          <Card className="min-w-0 shadow-none">
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 border-b border-border/60 px-4 py-2.5">
              <div>
                <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  {selected?.system
                    ? "System role (read-only)"
                    : selected
                      ? "Edit role"
                      : "Create role"}
                </CardTitle>
                {selected ? (
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {grantedCount} granted
                    {denied.size ? ` · ${denied.size} denied` : ""}
                  </p>
                ) : null}
              </div>
              {!selected?.system ? (
                <Button
                  size="sm"
                  disabled={busy || !draftName.trim() || !stepUp.trim()}
                  onClick={() => void saveRole()}
                >
                  <KeyRound className="size-3.5" />
                  Save role
                </Button>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-4 px-4 py-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <FieldLabel htmlFor="role-name">Name</FieldLabel>
                  <Input
                    id="role-name"
                    value={draftName}
                    disabled={Boolean(selected?.system) || busy}
                    onChange={(e) => setDraftName(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <FieldLabel htmlFor="role-stepup">Admin password (step-up)</FieldLabel>
                  <Input
                    id="role-stepup"
                    type="password"
                    value={stepUp}
                    disabled={Boolean(selected?.system) || busy}
                    onChange={(e) => setStepUp(e.target.value)}
                    autoComplete="current-password"
                    placeholder="Required to save"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <FieldLabel htmlFor="role-desc">Description</FieldLabel>
                <Input
                  id="role-desc"
                  value={draftDescription}
                  disabled={Boolean(selected?.system) || busy}
                  onChange={(e) => setDraftDescription(e.target.value)}
                  placeholder="Optional"
                />
              </div>

              <label
                className={cn(
                  "flex items-start gap-2.5 rounded-md border px-3 py-2.5 text-[13px]",
                  allowStar
                    ? "border-destructive/40 bg-destructive/10"
                    : "border-border/80 bg-muted/15",
                  selected?.system || busy ? "opacity-60" : "cursor-pointer hover:bg-muted/30",
                )}
              >
                <Checkbox
                  className="mt-0.5"
                  checked={allowStar}
                  disabled={Boolean(selected?.system) || busy}
                  onCheckedChange={(v) => setAllowStar(v === true)}
                />
                <span>
                  <span className="font-medium">Break-glass grant all tools (*)</span>
                  <span className="mt-0.5 block text-xs text-muted-foreground">
                    Requires explicit confirmation on save. Deny list still wins.
                  </span>
                </span>
              </label>

              <div className="rounded-md border border-border/80 bg-muted/10 px-3 py-2.5">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Effective access preview
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Input
                    id="effective-tool"
                    placeholder="tool name e.g. start_vm"
                    value={previewTool}
                    onChange={(e) => setPreviewTool(e.target.value)}
                    className="h-8 min-w-[12rem] flex-1 text-xs"
                  />
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={
                      !previewTool.trim() || (!selectedId && granted.size === 0 && !allowStar)
                    }
                    onClick={() => {
                      void (async () => {
                        try {
                          if (selectedId) {
                            const res = await AdminApi.accessEffective({
                              capability_role_id: selectedId,
                              tool_name: previewTool.trim(),
                            });
                            setPreviewResult(res.allowed ? "ALLOWED" : "DENIED");
                          } else {
                            const g = allowStar || granted.has(previewTool.trim());
                            const d = denied.has(previewTool.trim());
                            setPreviewResult(g && !d ? "ALLOWED (draft)" : "DENIED (draft)");
                          }
                        } catch (err) {
                          setPreviewResult(err instanceof Error ? err.message : "Preview failed");
                        }
                      })();
                    }}
                  >
                    Check
                  </Button>
                  {previewResult ? (
                    <Badge
                      variant="outline"
                      className={cn(
                        "font-mono text-[10px]",
                        previewResult.startsWith("ALLOWED")
                          ? "border-emerald-600/40 text-emerald-700 dark:text-emerald-400"
                          : "border-destructive/40 text-destructive",
                      )}
                    >
                      {previewResult}
                    </Badge>
                  ) : null}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <FieldLabel htmlFor="tool-filter">
                    Tools · deny-by-default ({filteredTools.length})
                  </FieldLabel>
                  <Input
                    id="tool-filter"
                    placeholder="Filter tools…"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="h-8 w-48 text-xs"
                  />
                </div>
                <div className="flex flex-wrap gap-1">
                  <Button
                    type="button"
                    size="xs"
                    variant={groupFilter === "all" ? "secondary" : "outline"}
                    onClick={() => setGroupFilter("all")}
                  >
                    all
                  </Button>
                  {Object.entries(groups).map(([g, names]) => (
                    <Button
                      key={g}
                      type="button"
                      size="xs"
                      variant={groupFilter === g ? "secondary" : "outline"}
                      onClick={() => setGroupFilter(g)}
                    >
                      {g}
                      <span className="ml-1 font-mono text-[10px] text-muted-foreground">
                        {names.length}
                      </span>
                    </Button>
                  ))}
                </div>
              </div>

              <div className="max-h-[min(28rem,55vh)] overflow-auto rounded-md border border-border">
                <Table>
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="h-8 w-12 px-3 text-[10px] uppercase">Grant</TableHead>
                      <TableHead className="h-8 px-3 text-[10px] uppercase">Tool</TableHead>
                      <TableHead className="h-8 w-24 px-3 text-[10px] uppercase">Risk</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredTools.map((tool) => {
                      const isGranted = granted.has(tool.name) || allowStar || granted.has("*");
                      return (
                        <TableRow
                          key={tool.name}
                          className={cn(isGranted && "bg-primary/5")}
                        >
                          <TableCell className="px-3 py-1.5">
                            <Checkbox
                              checked={isGranted}
                              disabled={Boolean(selected?.system) || busy || allowStar}
                              onCheckedChange={() => toggleGrant(tool.name)}
                            />
                          </TableCell>
                          <TableCell className="px-3 py-1.5">
                            <div className="font-mono text-[11px] leading-tight">{tool.name}</div>
                            <div className="mt-0.5 line-clamp-1 text-[10px] text-muted-foreground">
                              {tool.description}
                            </div>
                          </TableCell>
                          <TableCell className="px-3 py-1.5">
                            <Badge
                              variant="outline"
                              className={cn("text-[10px]", riskBadgeClass(tool.risk))}
                            >
                              {tool.risk}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
