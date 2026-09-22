from __future__ import annotations

from typing import cast

from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.observability import AlertRecord, InMemoryMetricsRegistry, ResourceTrend
from proxmox_mcp.proxmox import (
    InMemoryProxmoxApiClient,
    domain_tool_promotion_records,
    register_domain_completion_tools,
)
from proxmox_mcp.schemas.envelope import (
    Actor,
    RequestOptions,
    Target,
    ToolErrorResponse,
    ToolRequest,
    ToolResponse,
)
from proxmox_mcp.ssh import InMemorySshClient, SshCommandPolicy, SshCommandResult
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolGuardDecision, ToolRegistry


class WriteOnlyAuditWriter:
    async def write(self, event: object) -> None:
        _ = event


class FakeAuditEventRepository:
    def __init__(self, events: list[dict[str, object]]) -> None:
        self.events = events
        self.calls: list[dict[str, object]] = []

    async def list_events(
        self,
        *,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, object]]:
        self.calls.append({"limit": limit, "tenant_id": tenant_id})
        return self.events[:limit]


class FakeAlertBackend:
    def __init__(self, alerts: list[AlertRecord]) -> None:
        self.alerts = alerts
        self.calls: list[dict[str, object]] = []

    async def get_recent_alerts(
        self,
        *,
        limit: int,
        tenant_id: str | None,
        cluster_id: str | None,
        node_id: str | None,
    ) -> list[AlertRecord]:
        self.calls.append(
            {
                "limit": limit,
                "tenant_id": tenant_id,
                "cluster_id": cluster_id,
                "node_id": node_id,
            }
        )
        return self.alerts[:limit]


class FakeTrendBackend:
    def __init__(self, trends: list[ResourceTrend]) -> None:
        self.trends = trends
        self.calls: list[dict[str, object]] = []

    async def get_resource_trends(
        self,
        *,
        resource_type: str,
        resource_id: str,
        metric: str,
        range_seconds: int,
        step_seconds: int,
        limit: int,
    ) -> list[ResourceTrend]:
        self.calls.append(
            {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "metric": metric,
                "range_seconds": range_seconds,
                "step_seconds": step_seconds,
                "limit": limit,
            }
        )
        return self.trends[:limit]


class AllowGuard:
    async def evaluate(
        self,
        definition: ToolDefinition,
        request: ToolRequest,
        context: ToolExecutionContext,
    ) -> ToolGuardDecision:
        _ = definition, request, context
        return ToolGuardDecision.allowed()


def make_registry() -> ToolRegistry:
    registry = ToolRegistry(guard=AllowGuard())
    register_domain_completion_tools(registry)
    return registry


def make_request(
    *,
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="lab",
            node="pve-1",
            resource_type="vm",
            resource_id="100",
            vmid=100,
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_node_request(
    *,
    parameters: dict[str, object] | None = None,
    dry_run: bool = True,
) -> ToolRequest:
    return ToolRequest(
        actor=Actor(user_id="user_1", agent_id="agent_1", tenant_id="tenant_1"),
        target=Target(
            tenant_id="tenant_1",
            cluster="lab",
            node="pve-1",
            resource_type="node",
            resource_id="pve-1",
        ),
        parameters={} if parameters is None else parameters,
        options=RequestOptions(dry_run=dry_run),
    )


def make_context(
    request: ToolRequest,
    *,
    proxmox_client: InMemoryProxmoxApiClient | None = None,
    ssh_client: InMemorySshClient | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        proxmox_client=proxmox_client,
        ssh_client=ssh_client,
        ssh_command_policy=SshCommandPolicy(allowed_executables=frozenset({"zpool", "pvesh"})),
    )


def make_write_only_audit_context(request: ToolRequest) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=WriteOnlyAuditWriter(),
    )


def make_internal_context(
    request: ToolRequest,
    *,
    audit_repository: FakeAuditEventRepository | None = None,
    metrics_registry: InMemoryMetricsRegistry | None = None,
    alert_backend: FakeAlertBackend | None = None,
    trend_backend: FakeTrendBackend | None = None,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        request=request,
        settings=Settings(environment="test"),
        audit_writer=InMemoryAuditWriter(),
        audit_repository=audit_repository,
        metrics_registry=metrics_registry,
        alert_backend=alert_backend,
        trend_backend=trend_backend,
    )


async def test_domain_tool_dry_run_returns_endpoint_and_payload_without_calling_api() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"name": "vm-100"}})
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "create_vm",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests == []
    result = cast(dict[str, object], response.result)
    assert result["endpoint"] == "/nodes/pve-1/qemu"
    assert result["payload"] == {"name": "vm-100"}
    assert result["risk"] == "high"
    assert result["live_supported"] is True
    assert result["promotion_status"] == "live_supported"
    assert isinstance(result["impact"], dict)
    assert (
        result["rollback_guidance"] == "Verify target state and rollback path before live execution"
    )


async def test_domain_tool_live_run_calls_proxmox_api() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"service": "pvedaemon", "payload": {"state": "started"}},
        dry_run=False,
    )
    client = InMemoryProxmoxApiClient({"/nodes/pve-1/services/pvedaemon/state": "UPID:service"})

    response = await registry.execute(
        "start_node_service",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    assert client.requests[-1].method == "POST"
    assert client.requests[-1].path == "/nodes/pve-1/services/pvedaemon/state"


async def test_domain_ssh_tool_executes_command() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient(
        command_results={
            "zpool status -x": SshCommandResult(exit_status=0, stdout="all pools healthy")
        }
    )

    response = await registry.execute(
        "get_zfs_health",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    command_result = cast(dict[str, object], result["result"])
    assert command_result["stdout"] == "all pools healthy"


async def test_live_placeholder_mutation_returns_not_implemented() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute(
        "expand_storage",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert client.executions == []


async def test_enter_lxc_console_dry_run_previews_console_command() -> None:
    registry = make_registry()
    request = make_request()
    client = InMemorySshClient()

    response = await registry.execute(
        "enter_lxc_console",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["command"] == "pct enter 100"
    assert result["promotion_status"] == "live_supported"
    assert client.executions == []


async def test_target_backed_parameters_must_match_authorized_target() -> None:
    registry = make_registry()
    request = make_request(parameters={"vmid": 200}, dry_run=False)
    client = InMemorySshClient()

    response = await registry.execute(
        "enter_lxc_console",
        request,
        make_context(request, ssh_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.executions == []


async def test_target_metadata_must_match_resource_id() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    request.target.vmid = 200
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "reset_vm",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_unsupported_dry_run_does_not_advertise_placeholder_command() -> None:
    registry = make_registry()
    request = make_request()

    response = await registry.execute(
        "expand_storage",
        request,
        make_context(request),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["command"] is None


async def test_missing_endpoint_parameter_is_rejected() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "delete_bridge",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


async def test_unsafe_endpoint_parameter_is_rejected() -> None:
    registry = make_registry()
    request = make_request(parameters={"iface": "../vmbr0"}, dry_run=False)
    client = InMemoryProxmoxApiClient()

    response = await registry.execute(
        "delete_bridge",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
    assert client.requests == []


def test_domain_tool_schema_is_scoped_to_template_fields() -> None:
    registry = make_registry()
    schemas = {schema.name: schema.parameters_schema for schema in registry.schemas()}
    create_vm_schema = schemas["create_vm"]
    delete_bridge_schema = schemas["delete_bridge"]

    assert create_vm_schema is not None
    assert delete_bridge_schema is not None
    create_vm_properties = cast(dict[str, object], create_vm_schema["properties"])
    delete_bridge_properties = cast(dict[str, object], delete_bridge_schema["properties"])
    delete_bridge_required = cast(list[str], delete_bridge_schema["required"])
    assert "service" not in create_vm_properties
    assert "iface" in delete_bridge_properties
    assert "iface" in delete_bridge_required
    iface_schema = cast(dict[str, object], delete_bridge_properties["iface"])
    assert iface_schema["type"] == "string"


def test_domain_tool_schema_uses_concrete_union_for_vmid() -> None:
    registry = make_registry()
    schemas = {schema.name: schema.parameters_schema for schema in registry.schemas()}
    reset_vm_schema = schemas["reset_vm"]

    assert reset_vm_schema is not None
    properties = cast(dict[str, object], reset_vm_schema["properties"])
    vmid_schema = cast(dict[str, object], properties["vmid"])
    variants = cast(list[dict[str, object]], vmid_schema["anyOf"])
    assert {"type": "integer"} in variants
    assert {"type": "string"} in variants


def test_domain_promotion_records_define_replacement_criteria() -> None:
    records = {record.name: record for record in domain_tool_promotion_records()}

    assert set(records) >= {"create_vm", "create_zfs_pool", "expand_storage", "get_audit_events"}
    create_vm = records["create_vm"]
    assert create_vm.endpoint_template == "/nodes/{node}/qemu"
    assert create_vm.method == "POST"
    assert create_vm.path_fields == ("node",)
    assert create_vm.payload_field == "payload"
    assert create_vm.live_supported is True
    assert create_vm.lab_validation_required is True

    create_zfs_pool = records["create_zfs_pool"]
    assert create_zfs_pool.live_supported is True
    assert create_zfs_pool.promotion_status == "live_supported"
    assert create_zfs_pool.command_template == "zpool create {pool} {device}"

    expand_storage = records["expand_storage"]
    assert expand_storage.live_supported is False
    assert expand_storage.promotion_status == "guarded_not_implemented"
    assert "NOT_IMPLEMENTED" in expand_storage.failure_semantics

    get_audit_events = records["get_audit_events"]
    assert get_audit_events.promotion_status == "live_supported"
    assert get_audit_events.lab_validation_required is False

    get_prometheus_metrics = records["get_prometheus_metrics"]
    assert get_prometheus_metrics.promotion_status == "live_supported"
    assert get_prometheus_metrics.lab_validation_required is False

    get_recent_alerts = records["get_recent_alerts"]
    assert get_recent_alerts.promotion_status == "external_source_required"
    assert get_recent_alerts.lab_validation_required is False


def test_high_blast_radius_tools_remain_guarded_until_contracts_exist() -> None:
    records = {record.name: record for record in domain_tool_promotion_records()}

    for tool_name in (
        "verify_backup",
        "expand_storage",
        "apply_node_updates",
    ):
        record = records[tool_name]
        assert record.live_supported is False
        assert record.promotion_status == "guarded_not_implemented"
        assert "NOT_IMPLEMENTED" in record.failure_semantics

    enter_lxc_console = records["enter_lxc_console"]
    assert enter_lxc_console.live_supported is True
    assert enter_lxc_console.promotion_status == "live_supported"

    benchmark_storage = records["benchmark_storage"]
    assert benchmark_storage.live_supported is True
    assert benchmark_storage.promotion_status == "live_supported"


async def test_apply_node_updates_dry_run_returns_guarded_orchestration_plan() -> None:
    registry = make_registry()
    request = make_node_request(parameters={"payload": {"maintenance_window": "lab-only"}})

    response = await registry.execute("apply_node_updates", request, make_context(request))

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    update_plan = cast(dict[str, object], result["result"])
    assert result["promotion_status"] == "guarded_not_implemented"
    assert update_plan["execution_status"] == "guarded"
    assert update_plan["node"] == "pve-1"
    assert update_plan["maintenance_window"] == "lab-only"
    assert update_plan["preflight_checks"] == [
        "cluster_quorum",
        "node_health",
        "running_guests",
        "ha_resources",
        "storage_health",
        "verified_backups",
        "rollback_window",
    ]
    assert update_plan["audit_fields"] == [
        "node",
        "maintenance_window",
        "preflight_status",
        "execution_status",
        "rollback_guidance",
    ]


async def test_apply_node_updates_dry_run_collects_read_only_preflight_details() -> None:
    registry = make_registry()
    request = make_node_request(parameters={"payload": {"maintenance_window": "lab-only"}})
    client = InMemoryProxmoxApiClient(
        {
            "/cluster/status": [{"type": "cluster", "quorate": 1}],
            "/nodes/pve-1/status": {"status": "online"},
            "/nodes/pve-1/qemu": [{"vmid": 100, "status": "running"}],
            "/nodes/pve-1/lxc": [],
            "/cluster/ha/resources": [],
            "/nodes/pve-1/storage": [{"storage": "local", "active": 1, "enabled": 1}],
            "/nodes/pve-1/apt/update": [{"Package": "pve-manager", "OldVersion": "9.0"}],
        }
    )

    response = await registry.execute(
        "apply_node_updates",
        request,
        make_context(request, proxmox_client=client),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    update_plan = cast(dict[str, object], result["result"])
    assert update_plan["preflight_status"] == "blocked"
    assert update_plan["mutation_performed"] is False
    assert update_plan["preflight_details"] == {
        "quorum": "present",
        "node_status": "online",
        "running_guests": 1,
        "ha_resources": 0,
        "storage_health": "available",
        "pending_updates": 1,
        "backup_availability": "operator_required",
    }
    assert update_plan["blockers"] == ["running guests require drain evidence"]
    assert update_plan["rollback_guidance"] == (
        "Keep live updates guarded until drain, backup, reboot, reconnect, "
        "and rollback evidence exists"
    )


async def test_apply_node_updates_live_returns_update_specific_guard() -> None:
    registry = make_registry()
    request = make_node_request(
        parameters={"payload": {"maintenance_window": "lab-only"}},
        dry_run=False,
    )
    client = InMemorySshClient()

    response = await registry.execute(
        "apply_node_updates", request, make_context(request, ssh_client=client)
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"
    assert response.error.details == {
        "tool_name": "apply_node_updates",
        "connector": "hybrid",
        "required_evidence": (
            "node update orchestration preflight, rollback, reboot, and recovery lab evidence"
        ),
    }
    assert client.executions == []


async def test_get_audit_events_requires_queryable_repository() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)

    response = await registry.execute(
        "get_audit_events",
        request,
        make_write_only_audit_context(request),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "NOT_IMPLEMENTED"


async def test_get_audit_events_uses_queryable_repository() -> None:
    registry = make_registry()
    request = make_request(
        parameters={"payload": {"limit": 1}},
        dry_run=False,
    )
    repository = FakeAuditEventRepository(
        [
            {"event_id": "evt_1", "tenant_id": "tenant_1"},
            {"event_id": "evt_2", "tenant_id": "tenant_1"},
        ]
    )

    response = await registry.execute(
        "get_audit_events",
        request,
        make_internal_context(request, audit_repository=repository),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    assert result["result"] == [{"event_id": "evt_1", "tenant_id": "tenant_1"}]
    assert repository.calls == [{"limit": 1, "tenant_id": "tenant_1"}]


async def test_get_prometheus_metrics_uses_configured_metrics_registry() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)
    metrics = InMemoryMetricsRegistry()
    metrics.record_tool_invocation(
        tool_name="create_vm",
        connector="proxmox_api",
        status="success",
        duration_ms=42,
    )

    response = await registry.execute(
        "get_prometheus_metrics",
        request,
        make_internal_context(request, metrics_registry=metrics),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    internal_result = cast(dict[str, object], result["result"])
    assert internal_result["content_type"] == "text/plain; version=0.0.4"
    assert "proxmox_mcp_tool_invocations_total" in str(internal_result["metrics"])


async def test_external_observability_tools_require_explicit_sources() -> None:
    registry = make_registry()
    request = make_request(dry_run=False)

    response = await registry.execute(
        "get_recent_alerts",
        request,
        make_internal_context(request),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "EXTERNAL_SOURCE_REQUIRED"


async def test_get_recent_alerts_uses_configured_alert_backend() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"limit": 1}}, dry_run=False)
    backend = FakeAlertBackend(
        [
            AlertRecord(
                name="NodeDown",
                status="firing",
                severity="critical",
                starts_at="2026-06-06T00:00:00Z",
                labels={"alertname": "NodeDown", "node": "pve-1"},
                annotations={"summary": "node unavailable"},
                fingerprint="abc123",
            )
        ]
    )

    response = await registry.execute(
        "get_recent_alerts",
        request,
        make_internal_context(request, alert_backend=backend),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    alerts = cast(list[dict[str, object]], result["result"])
    assert alerts[0]["name"] == "NodeDown"
    assert alerts[0]["severity"] == "critical"
    assert backend.calls == [
        {
            "limit": 1,
            "tenant_id": "tenant_1",
            "cluster_id": "lab",
            "node_id": "pve-1",
        }
    ]


async def test_get_resource_trends_uses_configured_trend_backend() -> None:
    registry = make_registry()
    request = make_request(
        parameters={
            "payload": {
                "metric": "cpu_usage",
                "range_seconds": 3600,
                "step_seconds": 60,
                "limit": 1,
            }
        },
        dry_run=False,
    )
    backend = FakeTrendBackend(
        [
            ResourceTrend(
                resource_type="vm",
                resource_id="100",
                metric="cpu_usage",
                range_seconds=3600,
                step_seconds=60,
                samples=[{"timestamp": "2026-06-06T00:00:00Z", "value": 0.42}],
            )
        ]
    )

    response = await registry.execute(
        "get_resource_trends",
        request,
        make_internal_context(request, trend_backend=backend),
    )

    assert isinstance(response, ToolResponse)
    result = cast(dict[str, object], response.result)
    trends = cast(list[dict[str, object]], result["result"])
    assert trends[0]["metric"] == "cpu_usage"
    assert trends[0]["samples"] == [{"timestamp": "2026-06-06T00:00:00Z", "value": 0.42}]
    assert backend.calls == [
        {
            "resource_type": "vm",
            "resource_id": "100",
            "metric": "cpu_usage",
            "range_seconds": 3600,
            "step_seconds": 60,
            "limit": 1,
        }
    ]


async def test_get_resource_trends_rejects_invalid_window() -> None:
    registry = make_registry()
    request = make_request(parameters={"payload": {"range_seconds": 0}}, dry_run=False)

    response = await registry.execute(
        "get_resource_trends",
        request,
        make_internal_context(request, trend_backend=FakeTrendBackend([])),
    )

    assert isinstance(response, ToolErrorResponse)
    assert response.error.code == "INVALID_REQUEST"
