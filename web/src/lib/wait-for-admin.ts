const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_INTERVAL_MS = 1_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Poll GET /admin/api/me until the admin API responds with HTTP 200 (e.g. after MCP restart).
 */
export async function waitForAdminReady(opts?: {
  timeoutMs?: number;
  intervalMs?: number;
}): Promise<void> {
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const intervalMs = opts?.intervalMs ?? DEFAULT_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    try {
      const res = await fetch("/admin/api/me", {
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        return;
      }
    } catch {
      /* connection refused / network blip during restart */
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      break;
    }
    await sleep(Math.min(intervalMs, remaining));
  }

  throw new Error(`Admin API not ready within ${timeoutMs}ms`);
}
