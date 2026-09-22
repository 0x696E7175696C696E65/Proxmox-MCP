# Database Schema

## Overview

PostgreSQL is the authoritative store for identity mappings, sessions, RBAC assignments, policies, approvals, tool invocations, audit events, credential references, discovered resources, and SSH recordings. Redis is used for cache, rate limits, idempotency, distributed locks, and circuit breaker state.

The schema below is logical. Exact SQLAlchemy models and migrations will be generated during implementation.

## Core Tables

### tenants

- `id`
- `name`
- `slug`
- `environment`
- `created_at`
- `updated_at`

### users

- `id`
- `tenant_id`
- `external_subject`
- `display_name`
- `email`
- `status`
- `created_at`
- `updated_at`

### ai_agents

- `id`
- `tenant_id`
- `name`
- `provider`
- `model_family`
- `workload_identity`
- `status`
- `created_at`
- `updated_at`

### sessions

- `id`
- `tenant_id`
- `user_id`
- `agent_id`
- `auth_method`
- `started_at`
- `expires_at`
- `last_seen_at`
- `status`
- `metadata_json`

### proxmox_clusters

- `id`
- `tenant_id`
- `name`
- `api_endpoint`
- `tls_verify`
- `credential_ref_id`
- `environment`
- `status`
- `created_at`
- `updated_at`

### proxmox_nodes

- `id`
- `cluster_id`
- `name`
- `address`
- `fingerprint`
- `status`
- `last_seen_at`
- `metadata_json`

### resources

- `id`
- `tenant_id`
- `cluster_id`
- `node_id`
- `resource_type`
- `resource_id`
- `name`
- `tags`
- `pool`
- `storage_id`
- `status`
- `last_discovered_at`
- `metadata_json`

## Access Control Tables

### roles

- `id`
- `tenant_id`
- `name`
- `description`
- `built_in`
- `created_at`
- `updated_at`

### permissions

- `id`
- `name`
- `domain`
- `resource`
- `action`
- `description`

### role_permissions

- `role_id`
- `permission_id`

### role_assignments

- `id`
- `tenant_id`
- `subject_type`
- `subject_id`
- `role_id`
- `scope_json`
- `valid_from`
- `valid_until`
- `created_at`

### policies

- `id`
- `tenant_id`
- `name`
- `description`
- `effect`
- `operations`
- `conditions_json`
- `priority`
- `enabled`
- `created_at`
- `updated_at`

`effect` is one of `allow`, `deny`, or `require_approval`.

### dangerous_operation_settings

- `id`
- `tenant_id`
- `environment`
- `enabled`
- `require_approval`
- `log_full_command`
- `require_impact_analysis`
- `require_dry_run_when_supported`
- `require_target_revalidation`
- `settings_json`

## Secret Reference Tables

### credential_refs

- `id`
- `tenant_id`
- `name`
- `provider`
- `purpose`
- `reference`
- `version`
- `rotation_required_after`
- `last_rotated_at`
- `metadata_json`
- `created_at`
- `updated_at`

`reference` is a backend path or identifier, never a raw secret.

### credential_access_events

- `id`
- `tenant_id`
- `credential_ref_id`
- `session_id`
- `tool_invocation_id`
- `access_purpose`
- `result`
- `timestamp`

## Tool Execution Tables

### tool_invocations

- `id`
- `tenant_id`
- `session_id`
- `correlation_id`
- `request_id`
- `tool_name`
- `operation`
- `target_json`
- `input_hash`
- `idempotency_key`
- `dry_run`
- `risk_level`
- `risk_score`
- `policy_decision`
- `approval_request_id`
- `status`
- `started_at`
- `finished_at`
- `duration_ms`
- `error_code`
- `error_message`

### approvals

- `id`
- `tenant_id`
- `requested_by_user_id`
- `requested_by_agent_id`
- `operation`
- `target_hash`
- `input_hash`
- `risk_level`
- `risk_score`
- `impact_json`
- `status`
- `approval_mode`
- `expires_at`
- `created_at`
- `updated_at`

### approval_decisions

- `id`
- `approval_id`
- `approver_user_id`
- `decision`
- `reason`
- `decided_at`
- `metadata_json`

### idempotency_records

- `id`
- `tenant_id`
- `actor_hash`
- `tool_name`
- `target_hash`
- `input_hash`
- `idempotency_key`
- `result_hash`
- `result_json`
- `expires_at`
- `created_at`

## Audit Tables

### audit_events

- `id`
- `tenant_id`
- `event_id`
- `correlation_id`
- `event_type`
- `timestamp`
- `actor_user_id`
- `actor_agent_id`
- `session_id`
- `tool_invocation_id`
- `cluster_id`
- `node_id`
- `resource_type`
- `resource_id`
- `operation`
- `policy_decision`
- `approval_request_id`
- `result_status`
- `exit_code`
- `duration_ms`
- `event_json`
- `redacted`
- `previous_event_hash`
- `event_hash`

### audit_exports

- `id`
- `tenant_id`
- `sink_type`
- `sink_name`
- `last_event_id`
- `last_exported_at`
- `status`
- `error_message`

## SSH Tables

### ssh_sessions

- `id`
- `tenant_id`
- `cluster_id`
- `node_id`
- `session_id`
- `tool_invocation_id`
- `credential_ref_id`
- `ssh_username`
- `remote_address`
- `interactive`
- `started_at`
- `finished_at`
- `status`
- `exit_code`
- `metadata_json`

### ssh_commands

- `id`
- `tenant_id`
- `ssh_session_id`
- `tool_invocation_id`
- `command_hash`
- `command_redacted`
- `working_directory`
- `timeout_seconds`
- `started_at`
- `finished_at`
- `exit_code`
- `stdout_ref`
- `stderr_ref`
- `metadata_json`

### ssh_recordings

- `id`
- `tenant_id`
- `ssh_session_id`
- `storage_backend`
- `recording_ref`
- `sha256`
- `size_bytes`
- `started_at`
- `finished_at`
- `retention_until`

## Cache And Health Tables

### discovered_resource_snapshots

- `id`
- `tenant_id`
- `cluster_id`
- `snapshot_type`
- `snapshot_json`
- `created_at`
- `expires_at`

### connector_health

- `id`
- `tenant_id`
- `cluster_id`
- `node_id`
- `connector_type`
- `status`
- `circuit_state`
- `last_success_at`
- `last_failure_at`
- `failure_count`
- `metadata_json`

## Redis Keys

- `rate_limit:{tenant}:{actor}:{tool}`
- `session:{session_id}`
- `idempotency_lock:{tenant}:{key}`
- `circuit:{cluster}:{node}:{connector}`
- `api_cache:{cluster}:{endpoint_hash}`
- `approval_notify:{approval_id}`
- `distributed_lock:{resource_hash}`

## Retention

- Audit events: configurable, default 365 days or longer for regulated environments.
- SSH recordings: configurable, default 90 days for interactive sessions and 30 days for non-interactive command streams.
- Tool invocations: default 180 days.
- Idempotency records: default 24 hours unless a tool requires longer replay protection.
- Discovery snapshots: TTL-based, usually minutes to hours.
