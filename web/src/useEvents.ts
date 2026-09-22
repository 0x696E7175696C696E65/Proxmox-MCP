import { useEffect, useState } from "react";
import type { AuditEvent } from "./api";

type RuntimePayload = Record<string, unknown>;

export type EventsConnection = "connecting" | "live" | "reconnecting" | "offline";

export function useAdminEvents(onAudit: (event: AuditEvent) => void) {
  const [runtime, setRuntime] = useState<RuntimePayload | null>(null);
  const [connection, setConnection] = useState<EventsConnection>("connecting");

  useEffect(() => {
    let closed = false;
    let source: EventSource | null = null;
    let retryTimer: number | undefined;

    function connect() {
      if (closed) return;
      setConnection((prev) => (prev === "live" ? "live" : "connecting"));
      source = new EventSource("/admin/api/events", { withCredentials: true });

      source.onopen = () => {
        if (!closed) setConnection("live");
      };

      source.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data) as { type: string; payload: unknown };
          if (data.type === "audit.created") {
            onAudit(data.payload as AuditEvent);
          }
          if (data.type.startsWith("runtime.")) {
            setRuntime((prev) => ({ ...(prev ?? {}), ...(data.payload as RuntimePayload) }));
          }
        } catch {
          /* ignore malformed */
        }
      };

      source.onerror = () => {
        source?.close();
        source = null;
        if (closed) return;
        setConnection("reconnecting");
        retryTimer = window.setTimeout(connect, 2000);
      };
    }

    connect();

    return () => {
      closed = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      source?.close();
      setConnection("offline");
    };
  }, [onAudit]);

  return { runtime, connection };
}
