import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AdminApi } from "./api";
import { waitForAdminReady } from "./lib/wait-for-admin";

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: async () => body,
  };
}

describe("AdminApi hosts", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("lists hosts from GET /admin/api/hosts", async () => {
    const payload = {
      hosts: [
        {
          host_id: "homelab",
          name: "Homelab",
          api_endpoint: "https://192.168.10.137:8006",
          tls_verify: false,
          credential_ref_path: "clusters/homelab/proxmox-api",
          enabled: true,
          secrets_ready: true,
        },
      ],
      active_host_id: "homelab",
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(payload));
    vi.stubGlobal("fetch", fetchMock);

    const result = await AdminApi.hosts();

    expect(result).toEqual(payload);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/api/hosts",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("activateHost POSTs to activate endpoint", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        jsonResponse({
          ok: true,
          host_id: "pve-b",
          restarting: true,
          message: "Switching managed host; MCP is restarting",
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const result = await AdminApi.activateHost("pve-b");

    expect(result.restarting).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/api/hosts/pve-b/activate",
      expect.objectContaining({ method: "POST", credentials: "include" }),
    );
  });
});

describe("waitForAdminReady", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("resolves when GET /admin/api/me eventually returns 200", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, statusText: "Unavailable" })
      .mockResolvedValueOnce(jsonResponse({ user: {}, csrf_token: "t", expires_at: "" }));
    vi.stubGlobal("fetch", fetchMock);

    const ready = waitForAdminReady({ timeoutMs: 10_000, intervalMs: 1_000 });

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(ready).resolves.toBeUndefined();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledWith(
      "/admin/api/me",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("rejects when admin API stays unavailable until timeout", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 503, statusText: "Unavailable" }),
    );

    const ready = waitForAdminReady({ timeoutMs: 3_000, intervalMs: 1_000 });
    const assertion = expect(ready).rejects.toThrow(/not ready within 3000ms/i);

    await vi.advanceTimersByTimeAsync(3_500);
    await assertion;
  });
});
