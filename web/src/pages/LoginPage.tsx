import type { FormEvent } from "react";
import { useState } from "react";
import { Shield } from "lucide-react";
import { useAuth } from "../auth";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative grid min-h-svh place-items-center overflow-hidden bg-background px-4">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(to right, oklch(1 0 0 / 4%) 1px, transparent 1px), linear-gradient(to bottom, oklch(1 0 0 / 4%) 1px, transparent 1px)",
          backgroundSize: "28px 28px",
          maskImage: "radial-gradient(ellipse at center, black 20%, transparent 70%)",
        }}
      />
      <Card className="relative w-full max-w-[360px] border-border/80 shadow-none">
        <CardHeader className="gap-3 space-y-0 pb-3">
          <div className="flex size-8 items-center justify-center rounded-md border border-border bg-muted">
            <Shield className="size-4 text-primary" />
          </div>
          <div>
            <CardTitle className="text-base tracking-tight">Proxmox MCP</CardTitle>
            <CardDescription className="text-xs">Control plane sign-in</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <form className="space-y-3" onSubmit={onSubmit}>
            <div className="space-y-1.5">
              <Label htmlFor="username" className="text-xs">
                Username
              </Label>
              <Input
                id="username"
                className="h-8"
                value={username}
                autoFocus
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-xs">
                Password
              </Label>
              <Input
                id="password"
                type="password"
                className="h-8"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {error ? (
              <Alert variant="destructive" className="py-2">
                <AlertDescription className="text-xs">{error}</AlertDescription>
              </Alert>
            ) : null}
            <Button type="submit" className="h-8 w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
