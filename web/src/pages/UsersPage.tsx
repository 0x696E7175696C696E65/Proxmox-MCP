import { useEffect, useState } from "react";
import { Users } from "lucide-react";
import { AdminApi, type AdminUserRow } from "../api";
import { EmptyState } from "@/components/empty-state";
import { FieldLabel } from "@/components/form-section";
import { LoadingBlock } from "@/components/loading-block";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function UsersPage() {
  const [rows, setRows] = useState<AdminUserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [userPassword, setUserPassword] = useState("");
  const [role, setRole] = useState<"admin" | "operator" | "viewer">("operator");
  const [stepUp, setStepUp] = useState("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const data = await AdminApi.users();
    setRows(data.users);
  }

  useEffect(() => {
    void refresh()
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function createUser() {
    setBusy(true);
    setError(null);
    try {
      await AdminApi.createUser({
        username,
        user_password: userPassword,
        role,
        password: stepUp,
      });
      setMessage(`Created user ${username}`);
      setUsername("");
      setUserPassword("");
      setStepUp("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  async function setUserRole(user: AdminUserRow, nextRole: "admin" | "operator" | "viewer") {
    const password = window.prompt("Confirm your admin password (step-up)") ?? "";
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      await AdminApi.updateUser(user.user_id, { role: nextRole, password });
      setMessage(`Updated ${user.username} → ${nextRole}`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  async function toggleDisabled(user: AdminUserRow) {
    const password = window.prompt("Confirm your admin password (step-up)") ?? "";
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      await AdminApi.updateUser(user.user_id, {
        disabled: !user.disabled,
        password,
      });
      setMessage(`${user.disabled ? "Enabled" : "Disabled"} ${user.username}`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Users"
        description="Admin-only user management. Roles: admin (full), operator (no decide/users), viewer (read-only)."
      />

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {message ? (
        <Alert className="py-2">
          <AlertDescription className="text-xs">{message}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <Card className="h-fit shadow-none">
          <CardHeader className="px-4 py-3">
            <CardTitle className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Create user
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 px-4 pb-4">
            <div className="space-y-1">
              <FieldLabel>Username</FieldLabel>
              <Input value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="space-y-1">
              <FieldLabel>Password</FieldLabel>
              <Input
                type="password"
                value={userPassword}
                onChange={(e) => setUserPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <FieldLabel>Role</FieldLabel>
              <select
                className="h-9 w-full rounded-md border border-border bg-background px-2 text-sm"
                value={role}
                onChange={(e) => setRole(e.target.value as typeof role)}
              >
                <option value="admin">admin</option>
                <option value="operator">operator</option>
                <option value="viewer">viewer</option>
              </select>
            </div>
            <div className="space-y-1">
              <FieldLabel>Your password (step-up)</FieldLabel>
              <Input
                type="password"
                value={stepUp}
                onChange={(e) => setStepUp(e.target.value)}
              />
            </div>
            <Button
              size="sm"
              className="w-full"
              disabled={busy || !username || !userPassword || !stepUp}
              onClick={() => void createUser()}
            >
              Create
            </Button>
          </CardContent>
        </Card>

        <div className="min-w-0">
          {loading ? (
            <LoadingBlock label="Loading users…" />
          ) : rows.length === 0 ? (
            <EmptyState icon={Users} title="No users" description="Create an admin session user." />
          ) : (
            <div className="overflow-hidden rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Username</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Role</TableHead>
                    <TableHead className="h-8 px-3 text-[10px] uppercase">Status</TableHead>
                    <TableHead className="h-8 px-3 text-right text-[10px] uppercase">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((user) => (
                    <TableRow key={user.user_id}>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {user.username}
                      </TableCell>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">{user.role}</TableCell>
                      <TableCell className="px-3 py-2 font-mono text-[11px]">
                        {user.disabled ? "disabled" : "active"}
                      </TableCell>
                      <TableCell className="px-3 py-2">
                        <div className="flex justify-end gap-1.5">
                          <Button
                            size="xs"
                            variant="outline"
                            disabled={busy}
                            onClick={() => void setUserRole(user, "viewer")}
                          >
                            viewer
                          </Button>
                          <Button
                            size="xs"
                            variant="outline"
                            disabled={busy}
                            onClick={() => void setUserRole(user, "operator")}
                          >
                            operator
                          </Button>
                          <Button
                            size="xs"
                            variant="outline"
                            disabled={busy}
                            onClick={() => void setUserRole(user, "admin")}
                          >
                            admin
                          </Button>
                          <Button
                            size="xs"
                            variant="destructive"
                            disabled={busy}
                            onClick={() => void toggleDisabled(user)}
                          >
                            {user.disabled ? "Enable" : "Disable"}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
