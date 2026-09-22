import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { Eye, EyeOff, KeyRound } from "lucide-react";
import { AdminApi } from "../api";
import { useHostCatalog } from "@/components/host-switcher";
import { FieldLabel, FormSection } from "@/components/form-section";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { privacyFieldClass, usePrivacy } from "../privacy";
import { cn } from "@/lib/utils";

type Mask = { configured: boolean; last4: string | null };

export function SecretsPage() {
  const { hosts, activeHostId } = useHostCatalog();
  const { censor, enabled: privacyOn } = usePrivacy();
  const activeHost = hosts.find((h) => h.host_id === activeHostId) ?? null;
  const [secrets, setSecrets] = useState<Record<string, unknown> | null>(null);
  const [tokenId, setTokenId] = useState("");
  const [tokenSecret, setTokenSecret] = useState("");
  const [serviceToken, setServiceToken] = useState("");
  const [stepUpPassword, setStepUpPassword] = useState("");
  const [revealed, setRevealed] = useState<{ name: string; value: string } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    const data = await AdminApi.secrets();
    setSecrets(data);
    setTokenId(String(data.proxmox_token_id ?? ""));
  }

  useEffect(() => {
    void load().catch((err: Error) => setError(err.message));
  }, []);

  useEffect(() => {
    if (privacyOn) setRevealed(null);
  }, [privacyOn]);

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    if (!stepUpPassword) {
      setError("Confirm your password to save secrets");
      return;
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = { password: stepUpPassword };
      if (tokenId) body.proxmox_token_id = tokenId;
      if (tokenSecret) body.proxmox_token_secret = tokenSecret;
      if (serviceToken) body.service_token = serviceToken;
      if (secrets?.config_version) body.config_version = secrets.config_version;
      const result = await AdminApi.putSecrets(body);
      setMessage(String((result.result as Record<string, unknown>)?.message ?? "Saved"));
      setTokenSecret("");
      setServiceToken("");
      setStepUpPassword("");
      setRevealed(null);
      setSecrets(result.secrets as Record<string, unknown>);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function reveal(name: string) {
    setError(null);
    if (revealed?.name === name) {
      setRevealed(null);
      return;
    }
    if (!stepUpPassword) {
      setError("Confirm your password to reveal secrets");
      return;
    }
    try {
      const res = await AdminApi.revealSecret(name, stepUpPassword);
      setRevealed({ name, value: String(res.value ?? "") });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reveal failed");
    }
  }

  const proxMask = (secrets?.proxmox_token_secret ?? { configured: false, last4: null }) as Mask;
  const svcMask = (secrets?.service_token ?? { configured: false, last4: null }) as Mask;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Secrets"
        description="Proxmox API token and MCP service token. Values are masked by default."
        actions={
          <Button form="secrets-form" type="submit" size="sm" disabled={busy}>
            {busy ? "Saving…" : "Save secrets"}
          </Button>
        }
      />

      <form id="secrets-form" className="grid gap-4 lg:grid-cols-2" onSubmit={onSave}>
        <FormSection
          title="Step-up confirmation"
          description="Re-enter your admin password to save or reveal secrets."
        >
          <div className="space-y-1.5">
            <FieldLabel htmlFor="step-up">Password</FieldLabel>
            <Input
              id="step-up"
              type="password"
              className="h-8"
              value={stepUpPassword}
              onChange={(e) => setStepUpPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>
        </FormSection>

        <FormSection
          title="Proxmox API"
          description="Token used to call the active managed Proxmox host."
          actions={
            <Badge
              variant="outline"
              className={
                proxMask.configured
                  ? "rounded-sm border-transparent bg-[oklch(0.72_0.15_155/0.15)] font-mono text-[10px] uppercase text-[oklch(0.78_0.14_155)]"
                  : "rounded-sm font-mono text-[10px] uppercase text-muted-foreground"
              }
            >
              {proxMask.configured ? "set" : "missing"}
            </Badge>
          }
        >
          {activeHost ? (
            <Alert className="py-2">
              <AlertDescription className="text-xs text-muted-foreground">
                Active host{" "}
                <span className="font-medium text-foreground">{activeHost.name}</span> expects
                credentials at{" "}
                <span className="font-mono text-[11px] text-foreground">
                  {censor(activeHost.credential_ref_path)}
                </span>
                . Manage hosts on{" "}
                <NavLink to="/servers" className="text-primary underline underline-offset-2">
                  Servers
                </NavLink>
                .
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="space-y-1.5">
            <FieldLabel htmlFor="token-id">Token ID</FieldLabel>
            <Input
              id="token-id"
              className={cn("h-8 font-mono text-xs", privacyFieldClass(privacyOn))}
              value={tokenId}
              onChange={(e) => setTokenId(e.target.value)}
              placeholder="user@realm!tokenname"
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel
              htmlFor="token-secret"
              hint={
                proxMask.configured
                  ? privacyOn
                    ? "····••••"
                    : `····${proxMask.last4}`
                  : "not set"
              }
            >
              Token secret
            </FieldLabel>
            <Input
              id="token-secret"
              type="password"
              className={cn("h-8", privacyFieldClass(privacyOn))}
              value={tokenSecret}
              onChange={(e) => setTokenSecret(e.target.value)}
              placeholder="Leave blank to keep current"
              autoComplete="new-password"
            />
            <Button
              type="button"
              variant="outline"
              size="xs"
              disabled={!proxMask.configured || privacyOn}
              onClick={() => void reveal("proxmox_token_secret")}
            >
              {revealed?.name === "proxmox_token_secret" ? (
                <EyeOff className="size-3" />
              ) : (
                <Eye className="size-3" />
              )}
              {revealed?.name === "proxmox_token_secret" ? "Hide" : "Reveal"}
            </Button>
          </div>
        </FormSection>

        <FormSection
          title="MCP service token"
          description="Bearer token for MCP clients and health probes."
          actions={
            <Badge
              variant="outline"
              className={
                svcMask.configured
                  ? "rounded-sm border-transparent bg-[oklch(0.72_0.15_155/0.15)] font-mono text-[10px] uppercase text-[oklch(0.78_0.14_155)]"
                  : "rounded-sm font-mono text-[10px] uppercase text-muted-foreground"
              }
            >
              {svcMask.configured ? "set" : "missing"}
            </Badge>
          }
        >
          <div className="space-y-1.5">
            <FieldLabel
              htmlFor="service-token"
              hint={
                svcMask.configured
                  ? privacyOn
                    ? "····••••"
                    : `····${svcMask.last4}`
                  : "not set"
              }
            >
              Service token
            </FieldLabel>
            <Input
              id="service-token"
              type="password"
              className={cn("h-8", privacyFieldClass(privacyOn))}
              value={serviceToken}
              onChange={(e) => setServiceToken(e.target.value)}
              placeholder="Leave blank to keep current"
              autoComplete="new-password"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="xs"
                disabled={!svcMask.configured || privacyOn}
                onClick={() => void reveal("service_token")}
              >
                {revealed?.name === "service_token" ? (
                  <EyeOff className="size-3" />
                ) : (
                  <Eye className="size-3" />
                )}
                {revealed?.name === "service_token" ? "Hide" : "Reveal"}
              </Button>
              <p className="text-xs text-primary">
                Rotating this requires a{" "}
                <NavLink to="/runtime" className="underline underline-offset-2">
                  runtime restart
                </NavLink>
                .
              </p>
            </div>
          </div>
        </FormSection>

        {(message || error || revealed) && (
          <div className="space-y-2 lg:col-span-2">
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
            {revealed ? (
              <FormSection
                title="Revealed value"
                description="Hide when finished. This is not written to audit metadata."
                actions={<KeyRound className="size-3.5 text-muted-foreground" />}
              >
                <pre className="overflow-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-[11px]">
                  {censor(revealed.value)}
                </pre>
              </FormSection>
            ) : null}
          </div>
        )}
      </form>
    </div>
  );
}
