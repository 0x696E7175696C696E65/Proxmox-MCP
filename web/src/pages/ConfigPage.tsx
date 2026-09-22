import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { AdminApi } from "../api";
import { FieldLabel, FormSection } from "@/components/form-section";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function ConfigPage() {
  const [logLevel, setLogLevel] = useState("info");
  const [endpoint, setEndpoint] = useState("");
  const [tlsVerify, setTlsVerify] = useState(false);
  const [clusterName, setClusterName] = useState("");
  const [actorUser, setActorUser] = useState("operator");
  const [actorAgent, setActorAgent] = useState("homelab-agent");
  const [dangerEnabled, setDangerEnabled] = useState(true);
  const [requireApproval, setRequireApproval] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void AdminApi.config()
      .then((cfg) => {
        setLogLevel(String(cfg.log_level ?? "info"));
        const cluster = (cfg.cluster ?? {}) as Record<string, unknown>;
        setEndpoint(String(cluster.api_endpoint ?? ""));
        setTlsVerify(Boolean(cluster.tls_verify));
        setClusterName(String(cluster.name ?? ""));
        const actor = (cfg.default_actor ?? {}) as Record<string, unknown>;
        setActorUser(String(actor.user_id ?? "operator"));
        setActorAgent(String(actor.agent_id ?? "homelab-agent"));
        const danger = (cfg.dangerous_operations ?? {}) as Record<string, unknown>;
        setDangerEnabled(Boolean(danger.enabled));
        setRequireApproval(Boolean(danger.require_approval));
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      const result = await AdminApi.putConfig({
        log_level: logLevel,
        cluster_api_endpoint: endpoint || null,
        cluster_tls_verify: tlsVerify,
        cluster_name: clusterName || null,
        default_actor_user_id: actorUser,
        default_actor_agent_id: actorAgent,
        dangerous_operations_enabled: dangerEnabled,
        dangerous_operations_require_approval: requireApproval,
      });
      const apply = (result.result as Record<string, unknown>) ?? {};
      setMessage(String(apply.message ?? (apply.kind === "hot" ? "Applied hot" : "Saved")));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Apply failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Config"
        description="Non-secret runtime settings. Most changes hot-apply immediately."
        actions={
          <Button form="config-form" type="submit" size="sm" disabled={busy}>
            {busy ? "Applying…" : "Apply config"}
          </Button>
        }
      />

      <form id="config-form" className="grid gap-4 lg:grid-cols-2" onSubmit={onSave}>
        <FormSection title="Logging" description="Gateway log verbosity.">
          <div className="space-y-1.5">
            <FieldLabel htmlFor="log-level">Log level</FieldLabel>
            <Select
              value={logLevel}
              onValueChange={(value) => {
                if (value) setLogLevel(value);
              }}
            >
              <SelectTrigger id="log-level" className="w-full">
                <SelectValue placeholder="Select level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="debug">debug</SelectItem>
                <SelectItem value="info">info</SelectItem>
                <SelectItem value="warning">warning</SelectItem>
                <SelectItem value="error">error</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </FormSection>

        <FormSection title="Cluster" description="Proxmox API connectivity.">
          <div className="space-y-1.5">
            <FieldLabel htmlFor="endpoint">API endpoint</FieldLabel>
            <Input
              id="endpoint"
              className="h-8 font-mono text-xs"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="https://pve.example:8006"
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor="cluster-name">Cluster name</FieldLabel>
            <Input
              id="cluster-name"
              className="h-8"
              value={clusterName}
              onChange={(e) => setClusterName(e.target.value)}
            />
          </div>
          <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
            <Checkbox
              className="mt-0.5"
              checked={tlsVerify}
              onCheckedChange={(v) => setTlsVerify(v === true)}
            />
            <span>
              <span className="font-medium text-foreground">Verify Proxmox TLS</span>
              <span className="mt-0.5 block text-xs text-muted-foreground">
                Reject self-signed or mismatched certificates.
              </span>
            </span>
          </label>
        </FormSection>

        <FormSection title="Default actor" description="Attribution for gateway-initiated calls.">
          <div className="space-y-1.5">
            <FieldLabel htmlFor="actor-user">User ID</FieldLabel>
            <Input
              id="actor-user"
              className="h-8 font-mono text-xs"
              value={actorUser}
              onChange={(e) => setActorUser(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor="actor-agent">Agent ID</FieldLabel>
            <Input
              id="actor-agent"
              className="h-8 font-mono text-xs"
              value={actorAgent}
              onChange={(e) => setActorAgent(e.target.value)}
            />
          </div>
        </FormSection>

        <FormSection
          title="Dangerous operations"
          description="Gate high/critical mutations. Same policy as Approvals."
        >
          <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
            <Checkbox
              className="mt-0.5"
              checked={dangerEnabled}
              onCheckedChange={(v) => setDangerEnabled(v === true)}
            />
            <span>
              <span className="font-medium text-foreground">Dangerous operations enabled</span>
              <span className="mt-0.5 block text-xs text-muted-foreground">
                Allow high/critical tools when policy permits.
              </span>
            </span>
          </label>
          <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border/80 bg-muted/20 px-3 py-2.5 text-[13px] hover:bg-muted/35">
            <Checkbox
              className="mt-0.5"
              checked={requireApproval}
              onCheckedChange={(v) => setRequireApproval(v === true)}
            />
            <span>
              <span className="font-medium text-foreground">Require approval</span>
              <span className="mt-0.5 block text-xs text-muted-foreground">
                Queue dangerous ops for explicit approve/deny.
              </span>
            </span>
          </label>
        </FormSection>

        {(message || error) && (
          <div className="lg:col-span-2 space-y-2">
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
          </div>
        )}
      </form>
    </div>
  );
}
