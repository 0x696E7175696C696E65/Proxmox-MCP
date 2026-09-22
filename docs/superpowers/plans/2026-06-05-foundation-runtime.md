# Foundation Runtime Implementation Plan

> **Status:** Completed and superseded by the current preview-ready implementation. This document is retained as historical implementation context only; do not treat the unchecked task body below as the active roadmap.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first executable Python/FastMCP foundation for Enterprise Proxmox MCP with typed configuration, audit primitives, persistence wiring, health checks, and a no-op audited MCP tool.

**Architecture:** Keep the runtime small but real: `proxmox_mcp.config` owns settings, `proxmox_mcp.audit` owns structured audit events, `proxmox_mcp.persistence` owns SQLAlchemy and Redis wiring, and `proxmox_mcp.server` owns FastMCP registration. Security-sensitive execution modules are intentionally deferred until the foundation can validate config, emit audit events, and start cleanly.

**Tech Stack:** Python 3.13, FastMCP, Pydantic v2, pydantic-settings, SQLAlchemy async, asyncpg, redis-py asyncio, structlog, pytest, pytest-asyncio, ruff, pyright.

---

## File Structure

- `pyproject.toml`: package metadata, runtime dependencies, dev dependencies, ruff, pyright, and pytest configuration.
- `src/proxmox_mcp/__init__.py`: package version export.
- `src/proxmox_mcp/__main__.py`: `python -m proxmox_mcp` entrypoint.
- `src/proxmox_mcp/config.py`: typed runtime settings and secret-safe serialization.
- `src/proxmox_mcp/audit/events.py`: audit event Pydantic models.
- `src/proxmox_mcp/audit/writer.py`: audit writer protocol and in-memory writer for foundation tests.
- `src/proxmox_mcp/persistence/database.py`: async SQLAlchemy engine/session factory.
- `src/proxmox_mcp/persistence/redis.py`: Redis client factory.
- `src/proxmox_mcp/server/app.py`: FastMCP app factory, health payload, and no-op audited tool.
- `tests/test_package.py`: package metadata and entrypoint tests.
- `tests/test_config.py`: settings validation and secret redaction tests.
- `tests/test_audit.py`: audit event and writer tests.
- `tests/test_persistence.py`: database and Redis factory tests that do not require live services.
- `tests/test_server.py`: FastMCP app construction and health/no-op handler tests.
- `.github/workflows/ci.yml`: enable actual Python checks instead of disabled planned checks.

---

### Task 1: Package And Tooling Scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `src/proxmox_mcp/__init__.py`
- Create: `src/proxmox_mcp/__main__.py`
- Create: `tests/test_package.py`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write package metadata tests**

Create `tests/test_package.py`:

```python
import subprocess
import sys

from proxmox_mcp import __version__


def test_version_is_exposed() -> None:
    assert __version__ == "0.1.0"


def test_module_entrypoint_prints_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "proxmox_mcp", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "proxmox-mcp 0.1.0"
```

- [ ] **Step 2: Run the package test and confirm it fails**

Run: `python -m pytest tests/test_package.py -v`

Expected: fail because the `proxmox_mcp` package does not exist.

- [ ] **Step 3: Add package configuration and entrypoint**

Create `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "enterprise-proxmox-mcp"
version = "0.1.0"
description = "Enterprise-grade MCP server for secure Proxmox VE automation"
readme = "README.md"
requires-python = ">=3.13"
license = { text = "MIT" }
authors = [{ name = "0x696E7175696C696E65" }]
dependencies = [
  "asyncpg>=0.30",
  "fastmcp>=2.0",
  "pydantic>=2.11",
  "pydantic-settings>=2.9",
  "redis>=5.2",
  "sqlalchemy[asyncio]>=2.0",
  "structlog>=25.1",
]

[project.optional-dependencies]
dev = [
  "pip-audit>=2.7",
  "pyright>=1.1",
  "pytest>=8.3",
  "pytest-asyncio>=0.25",
  "ruff>=0.9",
]

[project.scripts]
proxmox-mcp = "proxmox_mcp.__main__:main"

[tool.hatch.build.targets.wheel]
packages = ["src/proxmox_mcp"]

[tool.pytest.ini_options]
addopts = "-ra"
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "ASYNC", "S"]
ignore = ["S101"]

[tool.pyright]
include = ["src", "tests"]
pythonVersion = "3.13"
typeCheckingMode = "strict"
```

Create `src/proxmox_mcp/__init__.py`:

```python
__version__ = "0.1.0"
```

Create `src/proxmox_mcp/__main__.py`:

```python
from __future__ import annotations

import argparse

from proxmox_mcp import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxmox-mcp")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.version:
        print(f"proxmox-mcp {__version__}")
        return 0

    from proxmox_mcp.server.app import run

    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Enable real CI checks**

Replace the disabled runtime job in `.github/workflows/ci.yml` with active install, format, lint, type-check, test, audit, and build steps using Python 3.13.

- [ ] **Step 5: Verify package tests pass**

Run: `python -m pip install -e ".[dev]"` then `python -m pytest tests/test_package.py -v`

Expected: both tests pass.

---

### Task 2: Typed Configuration

**Files:**
- Create: `src/proxmox_mcp/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write settings tests**

Create `tests/test_config.py`:

```python
from pydantic import SecretStr

from proxmox_mcp.config import DangerousOperationSettings, Settings


def test_settings_have_safe_defaults() -> None:
    settings = Settings()

    assert settings.environment == "development"
    assert settings.server_host == "127.0.0.1"
    assert settings.server_port == 8443
    assert settings.dangerous_operations.require_approval is True


def test_secret_values_are_redacted() -> None:
    settings = Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@db/app?ssl=require"))

    dumped = settings.safe_dump()

    assert dumped["database_url"] == "**********"
    assert "pass" not in str(dumped)


def test_dangerous_operations_can_be_disabled() -> None:
    settings = Settings(
        dangerous_operations=DangerousOperationSettings(enabled=False, require_approval=True)
    )

    assert settings.dangerous_operations.enabled is False
```

- [ ] **Step 2: Run settings tests and confirm they fail**

Run: `python -m pytest tests/test_config.py -v`

Expected: fail because `proxmox_mcp.config` does not exist.

- [ ] **Step 3: Implement settings**

Create `src/proxmox_mcp/config.py`:

```python
from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DangerousOperationSettings(BaseSettings):
    enabled: bool = True
    require_approval: bool = True
    log_full_command: bool = False
    require_impact_analysis: bool = True
    require_dry_run_when_supported: bool = True
    require_target_revalidation: bool = True


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROXMOX_MCP_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "staging", "production"] = "development"
    server_host: str = "127.0.0.1"
    server_port: int = Field(default=8443, ge=1, le=65535)
    database_url: SecretStr = SecretStr("postgresql+asyncpg://proxmox_mcp:proxmox_mcp@localhost/proxmox_mcp?ssl=require")
    redis_url: SecretStr = SecretStr("rediss://localhost:6379/0")
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    dangerous_operations: DangerousOperationSettings = Field(default_factory=DangerousOperationSettings)

    def safe_dump(self) -> dict[str, object]:
        return self.model_dump(mode="json")
```

- [ ] **Step 4: Verify settings tests pass**

Run: `python -m pytest tests/test_config.py -v`

Expected: 3 tests pass.

---

### Task 3: Audit Event Primitives

**Files:**
- Create: `src/proxmox_mcp/audit/__init__.py`
- Create: `src/proxmox_mcp/audit/events.py`
- Create: `src/proxmox_mcp/audit/writer.py`
- Create: `tests/test_audit.py`

- [ ] **Step 1: Write audit tests**

Create `tests/test_audit.py`:

```python
from proxmox_mcp.audit.events import AuditEvent, AuditTarget
from proxmox_mcp.audit.writer import InMemoryAuditWriter


def test_audit_event_contains_required_identity_fields() -> None:
    event = AuditEvent(
        event_type="tool.execution.started",
        correlation_id="corr_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status="started",
    )

    assert event.event_id.startswith("audit_")
    assert event.actor_user_id == "user_123"
    assert event.target.resource_type == "internal"


async def test_in_memory_audit_writer_records_events() -> None:
    writer = InMemoryAuditWriter()
    event = AuditEvent(
        event_type="tool.execution.finished",
        correlation_id="corr_123",
        actor_user_id="user_123",
        actor_agent_id="agent_123",
        tool_name="health_check",
        operation="internal.health.read",
        target=AuditTarget(resource_type="internal", resource_id="health"),
        result_status="success",
    )

    await writer.write(event)

    assert writer.events == [event]
```

- [ ] **Step 2: Run audit tests and confirm they fail**

Run: `python -m pytest tests/test_audit.py -v`

Expected: fail because audit modules do not exist.

- [ ] **Step 3: Implement audit models and writer**

Create `src/proxmox_mcp/audit/events.py` with Pydantic models for `AuditTarget` and `AuditEvent`. Use `uuid.uuid4().hex` to generate `audit_` event IDs.

Create `src/proxmox_mcp/audit/writer.py` with an `AuditWriter` protocol and `InMemoryAuditWriter` implementation.

Create `src/proxmox_mcp/audit/__init__.py` exporting the public audit types.

- [ ] **Step 4: Verify audit tests pass**

Run: `python -m pytest tests/test_audit.py -v`

Expected: 2 tests pass.

---

### Task 4: Persistence Factories

**Files:**
- Create: `src/proxmox_mcp/persistence/__init__.py`
- Create: `src/proxmox_mcp/persistence/database.py`
- Create: `src/proxmox_mcp/persistence/redis.py`
- Create: `tests/test_persistence.py`

- [ ] **Step 1: Write persistence factory tests**

Create `tests/test_persistence.py`:

```python
from pydantic import SecretStr

from proxmox_mcp.config import Settings
from proxmox_mcp.persistence.database import build_async_engine, build_session_factory
from proxmox_mcp.persistence.redis import build_redis_client


def test_database_engine_uses_configured_url() -> None:
    settings = Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@example/app?ssl=require"))

    engine = build_async_engine(settings)

    assert str(engine.url).startswith("postgresql+asyncpg://user:***@example/app")
    assert engine.url.query["ssl"] == "require"


def test_session_factory_is_bound_to_engine() -> None:
    settings = Settings(database_url=SecretStr("postgresql+asyncpg://user:pass@example/app?ssl=require"))
    engine = build_async_engine(settings)

    session_factory = build_session_factory(engine)

    assert session_factory.kw["bind"] is engine


def test_redis_client_uses_configured_url() -> None:
    settings = Settings(redis_url=SecretStr("rediss://redis.example:6379/5"))

    client = build_redis_client(settings)

    assert client.connection_pool.connection_kwargs["host"] == "redis.example"
    assert client.connection_pool.connection_kwargs["db"] == 5
```

- [ ] **Step 2: Run persistence tests and confirm they fail**

Run: `python -m pytest tests/test_persistence.py -v`

Expected: fail because persistence modules do not exist.

- [ ] **Step 3: Implement persistence factories**

Create database and Redis factories that accept `Settings`, unwrap `SecretStr` with `get_secret_value()`, and return unconnected clients/factories so tests do not require live services.

- [ ] **Step 4: Verify persistence tests pass**

Run: `python -m pytest tests/test_persistence.py -v`

Expected: 3 tests pass.

---

### Task 5: FastMCP App Factory And Health Tool

**Files:**
- Create: `src/proxmox_mcp/server/__init__.py`
- Create: `src/proxmox_mcp/server/app.py`
- Create: `tests/test_server.py`

- [ ] **Step 1: Write server tests**

Create `tests/test_server.py`:

```python
from proxmox_mcp.audit.writer import InMemoryAuditWriter
from proxmox_mcp.config import Settings
from proxmox_mcp.server.app import build_health_payload, build_server, health_check


def test_health_payload_reports_runtime_status() -> None:
    payload = build_health_payload(Settings(environment="test"))

    assert payload["status"] == "ok"
    assert payload["environment"] == "test"


def test_build_server_returns_named_app() -> None:
    app = build_server(Settings(environment="test"), InMemoryAuditWriter())

    assert app.name == "Enterprise Proxmox MCP"


async def test_health_check_writes_audit_event() -> None:
    writer = InMemoryAuditWriter()

    payload = await health_check(Settings(environment="test"), writer)

    assert payload["status"] == "ok"
    assert writer.events[0].tool_name == "health_check"
    assert writer.events[-1].result_status == "success"
```

- [ ] **Step 2: Run server tests and confirm they fail**

Run: `python -m pytest tests/test_server.py -v`

Expected: fail because server modules do not exist.

- [ ] **Step 3: Implement server app**

Create `src/proxmox_mcp/server/app.py` with:

- `build_health_payload(settings: Settings) -> dict[str, str | int]`
- `health_check(settings: Settings, audit_writer: AuditWriter) -> dict[str, str | int]`
- `build_server(settings: Settings | None = None, audit_writer: AuditWriter | None = None) -> FastMCP`
- `run() -> None`

Register a `health_check` MCP tool that calls the audited handler.

- [ ] **Step 4: Verify server tests pass**

Run: `python -m pytest tests/test_server.py -v`

Expected: 3 tests pass.

---

### Task 6: Full Verification

**Files:**
- Modify only files required to fix failures found by the checks below.

- [ ] **Step 1: Run format check**

Run: `python -m ruff format --check .`

Expected: pass.

- [ ] **Step 2: Run lint**

Run: `python -m ruff check .`

Expected: pass.

- [ ] **Step 3: Run type check**

Run: `python -m pyright`

Expected: pass.

- [ ] **Step 4: Run tests**

Run: `python -m pytest -v`

Expected: all tests pass.

- [ ] **Step 5: Review git diff**

Run: `git diff --stat` and `git status --short --branch`

Expected: changes are limited to the foundation runtime scaffold, tests, CI update, and this plan.
