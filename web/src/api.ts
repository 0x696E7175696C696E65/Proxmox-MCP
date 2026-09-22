export type AdminUser = { user_id: string; username: string; role?: "admin" | "operator" };

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function getCsrfToken() {
  return csrfToken;
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const method = (init.method ?? "GET").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const res = await fetch(path, { ...init, headers, credentials: "include" });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const AdminApi = {
  login: (username: string, password: string) =>
    api<{ user: AdminUser; csrf_token: string; expires_at: string }>(
      "/admin/api/auth/login",
      { method: "POST", body: JSON.stringify({ username, password }) },
    ),
  logout: () => api<{ ok: boolean }>("/admin/api/auth/logout", { method: "POST" }),
  me: () =>
    api<{ user: AdminUser; csrf_token: string; expires_at: string }>("/admin/api/me"),
  overview: () => api<Record<string, unknown>>("/admin/api/overview"),
  audit: (params: URLSearchParams) =>
    api<{ events: AuditEvent[]; next_cursor: string | null }>(
      `/admin/api/audit?${params.toString()}`,
    ),
  auditEvent: (id: string) => api<{ event: AuditEvent }>(`/admin/api/audit/${id}`),
  config: () => api<Record<string, unknown>>("/admin/api/config"),
  putConfig: (body: Record<string, unknown>) =>
    api<Record<string, unknown>>("/admin/api/config", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  secrets: () => api<Record<string, unknown>>("/admin/api/secrets"),
  putSecrets: (body: Record<string, unknown>) =>
    api<Record<string, unknown>>("/admin/api/secrets", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  revealSecret: (name: string, password: string) =>
    api<{ name: string; value: string | null }>("/admin/api/secrets/reveal", {
      method: "POST",
      body: JSON.stringify({ name, password }),
    }),
  runtime: () => api<Record<string, unknown>>("/admin/api/runtime"),
  restart: () =>
    api<{ ok: boolean; message: string }>("/admin/api/runtime/restart", {
      method: "POST",
    }),
  tools: (params?: URLSearchParams) =>
    api<{ tools: ToolSummary[]; count: number }>(
      `/admin/api/tools${params ? `?${params.toString()}` : ""}`,
    ),
  tool: (name: string) =>
    api<{
      tool: ToolSummary;
      parameters_schema: Record<string, unknown> | null;
      result_schema: Record<string, unknown> | null;
    }>(`/admin/api/tools/${encodeURIComponent(name)}`),
  invokeTool: (
    name: string,
    body: {
      target: Record<string, unknown>;
      parameters?: Record<string, unknown>;
      dry_run?: boolean;
    },
  ) =>
    api<{ tool: string; result: Record<string, unknown> }>(
      `/admin/api/tools/${encodeURIComponent(name)}/invoke`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  healthDeps: () => api<Record<string, unknown>>("/admin/api/health/deps"),
  healthDoctor: () =>
    api<{ ok: boolean; issues: Array<{ name: string; detail: string }> }>(
      "/admin/api/health/doctor",
      { method: "POST" },
    ),
  approvals: (params?: URLSearchParams) =>
    api<{ approvals: ApprovalRow[]; count: number }>(
      `/admin/api/approvals${params ? `?${params.toString()}` : ""}`,
    ),
  decideApproval: (id: string, decision: "approved" | "rejected", reason?: string) =>
    api<{ approval: ApprovalRow }>(`/admin/api/approvals/${encodeURIComponent(id)}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision, reason }),
    }),
  policy: () => api<{ dangerous_operations: Record<string, unknown> }>("/admin/api/policy"),
  putPolicy: (body: Record<string, unknown>) =>
    api<Record<string, unknown>>("/admin/api/policy", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  hosts: () => api<HostsResponse>("/admin/api/hosts"),
  createHost: (body: ManagedHostInput) =>
    api<{ host: ManagedHost }>("/admin/api/hosts", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateHost: (hostId: string, body: ManagedHostInput) =>
    api<{ host: ManagedHost }>(`/admin/api/hosts/${encodeURIComponent(hostId)}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteHost: (hostId: string) =>
    api<{ ok: boolean; host_id: string }>(
      `/admin/api/hosts/${encodeURIComponent(hostId)}`,
      { method: "DELETE" },
    ),
  activateHost: (hostId: string) =>
    api<ActivateHostResponse>(
      `/admin/api/hosts/${encodeURIComponent(hostId)}/activate`,
      { method: "POST" },
    ),
  probeHost: (hostId: string) =>
    api<{ host_id: string; health: HostHealth }>(
      `/admin/api/hosts/${encodeURIComponent(hostId)}/probe`,
      { method: "POST" },
    ),
};

export type HostHealth = {
  ok: boolean;
  version?: string;
  latency_ms?: number;
  error?: string;
};

export type ManagedHost = {
  host_id: string;
  name: string;
  api_endpoint: string;
  tls_verify: boolean;
  credential_ref_path: string;
  enabled: boolean;
  secrets_ready: boolean;
  health?: HostHealth;
};

/** Host catalog fields accepted on create/update (no server-derived fields). */
export type ManagedHostInput = Omit<ManagedHost, "secrets_ready" | "health">;

export type HostsResponse = {
  hosts: ManagedHost[];
  active_host_id: string | null;
};

export type ActivateHostResponse = {
  ok: boolean;
  host_id: string;
  restarting: boolean;
  message: string;
};

export type ToolSummary = {
  name: string;
  description: string;
  category: string;
  permission: string;
  risk: string;
  dry_run: boolean;
  approval_default: boolean;
  connector: string;
  invokable: boolean;
};

export type ApprovalRow = {
  approval_request_id: string;
  operation: string;
  actor_user_id: string;
  actor_agent_id: string;
  risk_level: string;
  risk_score: number;
  expires_at: string;
  status: string;
  consumed_at: string | null;
};

export type AuditEvent = {
  event_id: string;
  timestamp: string;
  tool_name: string;
  operation: string;
  actor_user_id: string;
  actor_agent_id: string;
  result_status: string;
  duration_ms?: number | null;
  error_code?: string | null;
  target?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};
