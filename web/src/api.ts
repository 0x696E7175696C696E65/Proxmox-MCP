export type AdminUser = {
  user_id: string;
  username: string;
  role?: "admin" | "operator" | "viewer";
  disabled?: boolean;
};

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
  restart: (password: string) =>
    api<{ ok: boolean; message: string }>("/admin/api/runtime/restart", {
      method: "POST",
      body: JSON.stringify({ password }),
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
  approval: (id: string) =>
    api<{ approval: ApprovalRow }>(`/admin/api/approvals/${encodeURIComponent(id)}`),
  decideApproval: (
    id: string,
    body: {
      decision: "approved" | "rejected";
      password: string;
      reason?: string;
    },
  ) =>
    api<{
      approval: ApprovalRow;
      approval_token?: string;
      approval_request_id?: string;
      expires_at?: string;
      retry_hint?: string;
    }>(`/admin/api/approvals/${encodeURIComponent(id)}/decide`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  policy: () => api<{ dangerous_operations: Record<string, unknown> }>("/admin/api/policy"),
  putPolicy: (body: {
    dangerous_operations_enabled?: boolean;
    dangerous_operations_require_approval?: boolean;
    password: string;
  }) =>
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
  activateHost: (hostId: string, password: string) =>
    api<ActivateHostResponse>(
      `/admin/api/hosts/${encodeURIComponent(hostId)}/activate`,
      { method: "POST", body: JSON.stringify({ password }) },
    ),
  probeHost: (hostId: string) =>
    api<{ host_id: string; health: HostHealth }>(
      `/admin/api/hosts/${encodeURIComponent(hostId)}/probe`,
      { method: "POST" },
    ),
  tasks: (params?: URLSearchParams) =>
    api<{ tasks: TaskRow[]; count: number }>(
      `/admin/api/tasks${params ? `?${params.toString()}` : ""}`,
    ),
  task: (upid: string) =>
    api<{ task: TaskRow }>(`/admin/api/tasks/${encodeURIComponent(upid)}`),
  refreshTask: (upid: string) =>
    api<{ task: TaskRow }>(`/admin/api/tasks/${encodeURIComponent(upid)}/refresh`, {
      method: "POST",
    }),
  inventorySummary: () =>
    api<{
      configured: boolean;
      detail?: string;
      nodes: Array<Record<string, unknown>>;
      vms: Array<Record<string, unknown>>;
      lxc: Array<Record<string, unknown>>;
      storage: Array<Record<string, unknown>>;
      counts?: Record<string, number>;
    }>("/admin/api/inventory/summary"),
  inventoryGuest: (guestType: string, guestId: string, node?: string) => {
    const params = node ? `?node=${encodeURIComponent(node)}` : "";
    return api<Record<string, unknown>>(
      `/admin/api/inventory/guests/${encodeURIComponent(guestType)}/${encodeURIComponent(guestId)}${params}`,
    );
  },
  observabilityOverview: () =>
    api<{
      configured: boolean;
      alertmanager: { configured: boolean };
      prometheus: { configured: boolean };
      alerts: Array<Record<string, unknown>>;
      trends: Array<Record<string, unknown>>;
      errors: string[];
    }>("/admin/api/observability/overview"),
  users: () => api<{ users: AdminUserRow[]; count: number }>("/admin/api/users"),
  createUser: (body: {
    username: string;
    user_password: string;
    role: "admin" | "operator" | "viewer";
    password: string;
  }) =>
    api<{ user: AdminUserRow }>("/admin/api/users", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateUser: (
    userId: string,
    body: {
      role?: "admin" | "operator" | "viewer";
      capability_role_id?: string | null;
      disabled?: boolean;
      user_password?: string;
      password: string;
    },
  ) =>
    api<{ user: AdminUserRow }>(`/admin/api/users/${encodeURIComponent(userId)}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  accessRoles: () =>
    api<{ roles: Array<Record<string, unknown>>; count: number }>("/admin/api/access/roles"),
  accessTools: () =>
    api<{
      tools: Array<Record<string, unknown>>;
      count: number;
      groups: Record<string, string[]>;
    }>("/admin/api/access/tools"),
  createAccessRole: (body: {
    name: string;
    description?: string;
    granted_tools: string[];
    denied_tools?: string[];
    allow_star?: boolean;
    password: string;
  }) =>
    api<{ role: Record<string, unknown> }>("/admin/api/access/roles", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAccessRole: (
    roleId: string,
    body: {
      name?: string;
      description?: string;
      granted_tools?: string[];
      denied_tools?: string[];
      allow_star?: boolean;
      password: string;
    },
  ) =>
    api<{ role: Record<string, unknown> }>(
      `/admin/api/access/roles/${encodeURIComponent(roleId)}`,
      { method: "PUT", body: JSON.stringify(body) },
    ),
  accessEffective: (body: {
    user_id?: string;
    capability_role_id?: string;
    tool_name?: string;
  }) =>
    api<{
      role: Record<string, unknown>;
      tool_name?: string | null;
      allowed?: boolean | null;
    }>("/admin/api/access/effective", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  testApprovalWebhook: (password: string) =>
    api<{ ok: boolean; delivery: Record<string, unknown> }>(
      "/admin/api/approvals/webhook/test",
      { method: "POST", body: JSON.stringify({ password }) },
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
  summary?: Record<string, unknown> | null;
  decided_by?: string | null;
  reason?: string | null;
  decided_at?: string | null;
  required_approvals?: number;
  approval_count?: number;
  decisions?: Array<{
    approver_username?: string;
    decision?: string;
    created_at?: string;
  }>;
};

export type TaskRow = {
  task_id: string;
  upid: string;
  operation: string;
  method: string;
  endpoint: string;
  target: Record<string, unknown>;
  status: string;
  retryable: boolean;
  last_observed_state: string | null;
  created_at: string;
  updated_at: string;
  node?: string | null;
};

export type AdminUserRow = {
  user_id: string;
  username: string;
  role: "admin" | "operator" | "viewer" | string;
  capability_role_id?: string | null;
  disabled?: boolean;
  created_at?: string | null;
  last_login_at?: string | null;
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
