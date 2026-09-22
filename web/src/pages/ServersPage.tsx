import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  HardDrive,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  Zap,
} from "lucide-react";
import {
  AdminApi,
  type ManagedHost,
  type ManagedHostInput,
} from "../api";
import {
  shortHostLabel,
  useHostCatalog,
} from "@/components/host-switcher";
import { EmptyState } from "@/components/empty-state";
import { FieldLabel, FormSection } from "@/components/form-section";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { privacyFieldClass, usePrivacy } from "../privacy";
import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const emptyForm = (): ManagedHostInput => ({
  host_id: "",
  name: "",
  api_endpoint: "",
  tls_verify: false,
  credential_ref_path: "",
  enabled: true,
});

function defaultCredPath(hostId: string) {
  const id = hostId.trim();
  return id ? `clusters/${id}/proxmox-api` : "";
}

export function ServersPage() {
  const {
    hosts,
    activeHostId,
    loading,
    reload,
    mergeHostHealth,
    requestActivate,
    canSwitch,
  } = useHostCatalog();
  const { censor, enabled: privacyOn } = usePrivacy();
  const [form, setForm] = useState<ManagedHostInput>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [probing, setProbing] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  const sorted = useMemo(
    () =>
      [...hosts].sort((a, b) => {
        if (a.host_id === activeHostId) return -1;
        if (b.host_id === activeHostId) return 1;
        return a.name.localeCompare(b.name);
      }),
    [hosts, activeHostId],
  );

  useEffect(() => {
    if (!editingId && form.host_id && !form.credential_ref_path) {
      setForm((f) => ({ ...f, credential_ref_path: defaultCredPath(f.host_id) }));
    }
  }, [form.host_id, form.credential_ref_path, editingId]);

  function startCreate() {
    setEditingId(null);
    setForm(emptyForm());
    setShowForm(true);
    setError(null);
    setMessage(null);
  }

  function startEdit(host: ManagedHost) {
    setEditingId(host.host_id);
    setForm({
      host_id: host.host_id,
      name: host.name,
      api_endpoint: host.api_endpoint,
      tls_verify: host.tls_verify,
      credential_ref_path: host.credential_ref_path,
      enabled: host.enabled,
    });
    setShowForm(true);
    setError(null);
    setMessage(null);
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const body: ManagedHostInput = {
        ...form,
        host_id: form.host_id.trim(),
        name: form.name.trim(),
        api_endpoint: form.api_endpoint.trim(),
        credential_ref_path:
          form.credential_ref_path.trim() || defaultCredPath(form.host_id),
      };
      if (editingId) {
        await AdminApi.updateHost(editingId, body);
        setMessage(`Updated ${body.name}`);
      } else {
        await AdminApi.createHost(body);
        setMessage(`Added ${body.name}`);
      }
      setShowForm(false);
      setEditingId(null);
      setForm(emptyForm());
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(host: ManagedHost) {
    if (host.host_id === activeHostId) return;
    if (
      !window.confirm(
        `Delete managed server “${host.name}”? This does not remove secrets.`,
      )
    ) {
      return;
    }
    setError(null);
    setMessage(null);
    try {
      await AdminApi.deleteHost(host.host_id);
      setMessage(`Deleted ${host.name}`);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  }

  async function onProbe(host: ManagedHost) {
    setProbing(host.host_id);
    setError(null);
    try {
      const res = await AdminApi.probeHost(host.host_id);
      mergeHostHealth(host.host_id, res.health);
      setMessage(
        res.health.ok
          ? `Probe OK · ${res.health.version ?? "version unknown"}${
              res.health.latency_ms != null ? ` · ${res.health.latency_ms}ms` : ""
            }`
          : `Probe failed: ${res.health.error ?? "unreachable"}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Probe failed");
    } finally {
      setProbing(null);
    }
  }

  if (loading && hosts.length === 0) {
    return <LoadingBlock label="Loading managed servers…" />;
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Servers"
        description="Independent Proxmox hosts. Exactly one is active; switching rewrites cluster env and restarts MCP."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => void reload()}
            >
              <RefreshCw className="size-3.5" />
              Refresh
            </Button>
            <Button type="button" size="sm" onClick={startCreate}>
              <Plus className="size-3.5" />
              Add host
            </Button>
          </div>
        }
      />

      {message ? (
        <Alert className="py-2">
          <AlertDescription className="text-xs text-[oklch(0.78_0.14_155)]">
            {message}
          </AlertDescription>
        </Alert>
      ) : null}
      {error ? (
        <Alert variant="destructive" className="py-2">
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      ) : null}

      {showForm ? (
        <FormSection
          title={editingId ? "Edit host" : "Add host"}
          description="Credential path defaults to clusters/{host_id}/proxmox-api. Store the token under that path on Secrets before activating."
          actions={
            <Button
              type="button"
              size="xs"
              variant="ghost"
              onClick={() => {
                setShowForm(false);
                setEditingId(null);
              }}
            >
              Close
            </Button>
          }
        >
          <form className="grid gap-3 sm:grid-cols-2" onSubmit={onSubmit}>
            <div className="space-y-1.5">
              <FieldLabel htmlFor="host-id">Host ID</FieldLabel>
              <Input
                id="host-id"
                className="h-8 font-mono text-xs"
                value={form.host_id}
                disabled={Boolean(editingId)}
                onChange={(e) => {
                  const host_id = e.target.value;
                  setForm((f) => ({
                    ...f,
                    host_id,
                    credential_ref_path:
                      !editingId &&
                      (!f.credential_ref_path ||
                        f.credential_ref_path === defaultCredPath(f.host_id))
                        ? defaultCredPath(host_id)
                        : f.credential_ref_path,
                  }));
                }}
                placeholder="pve-b"
                required
              />
            </div>
            <div className="space-y-1.5">
              <FieldLabel htmlFor="host-name">Display name</FieldLabel>
              <Input
                id="host-name"
                className="h-8 text-xs"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="Lab NUC"
                required
              />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <FieldLabel htmlFor="host-endpoint">API endpoint</FieldLabel>
              <Input
                id="host-endpoint"
                className={cn("h-8 font-mono text-xs", privacyFieldClass(privacyOn))}
                value={form.api_endpoint}
                onChange={(e) =>
                  setForm((f) => ({ ...f, api_endpoint: e.target.value }))
                }
                placeholder="https://192.168.10.200:8006"
                required
              />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <FieldLabel htmlFor="host-cred">Credential path</FieldLabel>
              <Input
                id="host-cred"
                className={cn("h-8 font-mono text-xs", privacyFieldClass(privacyOn))}
                value={form.credential_ref_path}
                onChange={(e) =>
                  setForm((f) => ({ ...f, credential_ref_path: e.target.value }))
                }
                placeholder="clusters/pve-b/proxmox-api"
                required
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <Checkbox
                checked={form.tls_verify}
                onCheckedChange={(v) =>
                  setForm((f) => ({ ...f, tls_verify: v === true }))
                }
              />
              TLS verify
            </label>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <Checkbox
                checked={form.enabled}
                onCheckedChange={(v) =>
                  setForm((f) => ({ ...f, enabled: v === true }))
                }
              />
              Enabled in switcher
            </label>
            <div className="flex flex-wrap gap-2 sm:col-span-2">
              <Button type="submit" size="sm" disabled={busy}>
                {busy ? <Loader2 className="size-3.5 animate-spin" /> : null}
                {editingId ? "Save changes" : "Create host"}
              </Button>
            </div>
          </form>
        </FormSection>
      ) : null}

      {sorted.length === 0 ? (
        <EmptyState
          icon={HardDrive}
          title="No managed servers yet"
          description="Register two independent Proxmox hosts (not a corosync cluster). Only one is active at a time — switching restarts MCP so tools talk to that host only."
          action={
            <Button type="button" size="sm" onClick={startCreate}>
              <Plus className="size-3.5" />
              Add first host
            </Button>
          }
        />
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-9 text-[10px] uppercase tracking-[0.12em]">
                  Host
                </TableHead>
                <TableHead className="h-9 text-[10px] uppercase tracking-[0.12em]">
                  Endpoint
                </TableHead>
                <TableHead className="h-9 text-[10px] uppercase tracking-[0.12em]">
                  Secrets
                </TableHead>
                <TableHead className="h-9 text-[10px] uppercase tracking-[0.12em]">
                  Health
                </TableHead>
                <TableHead className="h-9 text-right text-[10px] uppercase tracking-[0.12em]">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.map((host) => {
                const isActive = host.host_id === activeHostId;
                return (
                  <TableRow
                    key={host.host_id}
                    className={cn(isActive && "bg-primary/5")}
                  >
                    <TableCell className="align-top">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[13px] font-medium">{host.name}</span>
                          {isActive ? (
                            <Badge
                              variant="outline"
                              className="rounded-sm border-primary/35 bg-primary/10 font-mono text-[9px] uppercase text-primary"
                            >
                              Active
                            </Badge>
                          ) : null}
                          {!host.enabled ? (
                            <Badge
                              variant="outline"
                              className="rounded-sm font-mono text-[9px] uppercase text-muted-foreground"
                            >
                              Disabled
                            </Badge>
                          ) : null}
                        </div>
                        <div className="font-mono text-[10px] text-muted-foreground">
                          {host.host_id}
                        </div>
                        <div className="font-mono text-[10px] text-muted-foreground">
                          {censor(host.credential_ref_path)}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="align-top">
                      <div className="font-mono text-[11px]">
                        {censor(shortHostLabel(host.api_endpoint))}
                      </div>
                      <div className="mt-0.5 max-w-[220px] truncate font-mono text-[10px] text-muted-foreground">
                        {censor(host.api_endpoint)}
                      </div>
                      <div className="mt-0.5 text-[10px] text-muted-foreground">
                        TLS verify: {String(host.tls_verify)}
                      </div>
                    </TableCell>
                    <TableCell className="align-top">
                      <Badge
                        variant="outline"
                        className={cn(
                          "rounded-sm font-mono text-[9px] uppercase",
                          host.secrets_ready
                            ? "border-transparent bg-[oklch(0.72_0.15_155/0.15)] text-[oklch(0.78_0.14_155)]"
                            : "text-muted-foreground",
                        )}
                      >
                        {host.secrets_ready ? "ready" : "missing"}
                      </Badge>
                      {!host.secrets_ready ? (
                        <div className="mt-1">
                          <NavLink
                            to="/secrets"
                            className="text-[10px] text-primary underline underline-offset-2"
                          >
                            Add on Secrets
                          </NavLink>
                        </div>
                      ) : null}
                    </TableCell>
                    <TableCell className="align-top">
                      {host.health == null ? (
                        <span className="text-[11px] text-muted-foreground">—</span>
                      ) : host.health.ok ? (
                        <div className="space-y-0.5">
                          <span className="text-[11px] text-[oklch(0.78_0.14_155)]">
                            OK
                          </span>
                          {host.health.version ? (
                            <div className="font-mono text-[10px] text-muted-foreground">
                              {host.health.version}
                            </div>
                          ) : null}
                        </div>
                      ) : (
                        <span
                          className="text-[11px] text-[oklch(0.75_0.16_75)]"
                          title={host.health.error}
                        >
                          Warn
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="align-top">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        <Button
                          type="button"
                          size="xs"
                          variant="outline"
                          disabled={probing === host.host_id}
                          onClick={() => void onProbe(host)}
                        >
                          {probing === host.host_id ? (
                            <Loader2 className="size-3 animate-spin" />
                          ) : (
                            <Zap className="size-3" />
                          )}
                          Probe
                        </Button>
                        <Button
                          type="button"
                          size="xs"
                          variant="outline"
                          disabled={!canSwitch || isActive || !host.enabled}
                          onClick={() => requestActivate(host)}
                          title={
                            !host.secrets_ready
                              ? "Secrets required — confirm dialog will block"
                              : undefined
                          }
                        >
                          Activate
                        </Button>
                        <Button
                          type="button"
                          size="xs"
                          variant="ghost"
                          onClick={() => startEdit(host)}
                        >
                          <Pencil className="size-3" />
                          Edit
                        </Button>
                        <Button
                          type="button"
                          size="xs"
                          variant="ghost"
                          className="text-destructive"
                          disabled={isActive}
                          onClick={() => void onDelete(host)}
                        >
                          <Trash2 className="size-3" />
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
