from typing import cast

from sqlalchemy import Table

from proxmox_mcp.persistence.models import AuditEventRecord, Base


def test_audit_events_table_has_expected_core_columns() -> None:
    table = cast(Table, AuditEventRecord.__table__)

    expected_columns = {
        "event_id",
        "timestamp",
        "event_type",
        "correlation_id",
        "tenant_id",
        "actor_user_id",
        "actor_agent_id",
        "tool_name",
        "operation",
        "resource_type",
        "resource_id",
        "cluster_id",
        "node_id",
        "result_status",
        "exit_code",
        "duration_ms",
        "error_code",
        "target_json",
        "metadata_json",
        "event_json",
    }

    assert table.name == "audit_events"
    assert table in Base.metadata.tables.values()
    assert expected_columns.issubset(table.c.keys())
    assert "previous_event_hash" not in table.c
    assert "event_hash" not in table.c
    assert list(table.primary_key.columns.keys()) == ["event_id"]
