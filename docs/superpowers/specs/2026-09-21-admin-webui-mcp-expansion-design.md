# Admin WebUI Expansion — MCP Control Plane v1.5

Date: 2026-09-21  
Status: approved  
Scope: Deeper MCP control plane (not Proxmox ops console)

## Decisions

| Topic | Choice |
|-------|--------|
| Product direction | A — Deeper MCP control plane |
| Delivery order | 1 Tools → 2 Health → 3 Approvals |
| Architecture | Admin API wrappers (cookie+CSRF); never browser→`/mcp` with service token |
| Tool invoke risk | UI can run low/medium; high/critical blocked or routed via Approvals |

## Goals

1. **Tools console** — browse registered tools + schemas; invoke safe tools; show result + audit linkage  
2. **Health & deps** — full dependency matrix + doctor diagnostics  
3. **Approvals & policy** — pending queue approve/deny; dangerous-ops policy strip  

## Non-goals

- Proxmox VM/LXC management UI  
- Putting MCP Bearer tokens in the browser  
- Changing agent `/mcp` auth model  

## Admin API additions

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/api/tools` | List tools (name, risk, description, schema summary) |
| GET | `/admin/api/tools/{name}` | Tool detail + JSON schema |
| POST | `/admin/api/tools/{name}/invoke` | Invoke tool as admin-ui actor (guarded) |
| GET | `/admin/api/health/deps` | Dependency checker results |
| POST | `/admin/api/health/doctor` | Run doctor checks |
| GET | `/admin/api/approvals` | List pending (and recent) approvals |
| POST | `/admin/api/approvals/{id}/decide` | approve \| deny + reason |
| GET/PUT | `/admin/api/policy` | dangerous_operations enabled / require_approval |

## SPA pages

- Tools, Health, Approvals in sidebar  
- Precision ops visual language unchanged  

## Security

- Admin session required + CSRF on mutating routes  
- Invokes go through existing ToolRegistry + SecurityGuard  
- Actor: `admin` / `admin-ui`  
- All actions audited  

## Test plan

- Pytest: tools list/invoke gate, health deps, approvals decide, CSRF  
- SPA build green  
- Manual: login → Tools invoke read → Health → Approvals policy toggle  
