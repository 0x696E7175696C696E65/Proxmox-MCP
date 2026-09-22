import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

const STORAGE_KEY = "proxmox-mcp.privacy";

type PrivacyState = {
  enabled: boolean;
  setEnabled: (value: boolean) => void;
  toggle: () => void;
  censor: (value: string) => string;
};

const PrivacyContext = createContext<PrivacyState | null>(null);

/** Redact IPs, URL hosts/ports, and credential paths for display. */
export function censorText(value: string): string {
  if (!value) return value;
  let out = value;

  // IPv4 (and host:port leftovers)
  out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "•••.••.••.•••");

  // IPv6 (coarse)
  out = out.replace(
    /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi,
    "••••:••••:••••:••••",
  );

  // URL host (non-IP hostnames)
  out = out.replace(
    /(https?:\/\/)([^/\s?#]+)/gi,
    (_m, proto: string, hostport: string) => {
      const [host, port] = hostport.split(":");
      if (/^•/.test(host)) {
        return `${proto}${hostport}`;
      }
      const maskedHost = host.length <= 4 ? "••••" : `${host.slice(0, 2)}••••`;
      return port ? `${proto}${maskedHost}:••••` : `${proto}${maskedHost}`;
    },
  );

  // bare host:port after protocol strip (e.g. shortHostLabel)
  out = out.replace(
    /\b([a-z0-9][a-z0-9.-]*[a-z0-9]):(\d{2,5})\b/gi,
    (m, host: string, _port: string) => {
      if (/^•/.test(host) || /^(?:\d+\.){3}/.test(host)) return m;
      return `${host.slice(0, 2)}••••:••••`;
    },
  );

  // credential / secret paths
  out = out.replace(
    /\bclusters\/[^/\s]+\/[^\s]+/g,
    "clusters/••••/••••",
  );
  out = out.replace(
    /\b(?:token_id|token_secret|service_token)\b/gi,
    "••••••••",
  );

  return out;
}

export function PrivacyProvider({ children }: { children: ReactNode }) {
  const [enabled, setEnabledState] = useState(() => {
    try {
      return window.localStorage.getItem(STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });

  const setEnabled = useCallback((value: boolean) => {
    setEnabledState(value);
    try {
      window.localStorage.setItem(STORAGE_KEY, value ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, []);

  const toggle = useCallback(() => {
    setEnabled(!enabled);
  }, [enabled, setEnabled]);

  useEffect(() => {
    document.documentElement.dataset.privacy = enabled ? "on" : "off";
  }, [enabled]);

  const censor = useCallback(
    (value: string) => (enabled ? censorText(value) : value),
    [enabled],
  );

  const value = useMemo(
    () => ({ enabled, setEnabled, toggle, censor }),
    [enabled, setEnabled, toggle, censor],
  );

  return (
    <PrivacyContext.Provider value={value}>{children}</PrivacyContext.Provider>
  );
}

export function usePrivacy() {
  const ctx = useContext(PrivacyContext);
  if (!ctx) {
    throw new Error("usePrivacy requires PrivacyProvider");
  }
  return ctx;
}

/** Display helper — censors when privacy mode is on. */
export function Sensitive({
  children,
  className,
}: {
  children: string;
  className?: string;
}) {
  const { censor, enabled } = usePrivacy();
  return (
    <span
      className={className}
      title={enabled ? "Hidden while privacy mode is on" : undefined}
    >
      {censor(children)}
    </span>
  );
}

/** Soft blur for form fields that still need to keep real values editable. */
export function privacyFieldClass(enabled: boolean): string {
  return enabled
    ? "blur-[5px] transition-[filter] duration-200 focus-within:blur-none focus:blur-none"
    : "transition-[filter] duration-200";
}
