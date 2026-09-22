export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const sec = Math.round((Date.now() - t) / 1000);
  const future = sec < 0;
  const abs = Math.abs(sec);
  let label: string;
  if (abs < 60) label = `${abs}s`;
  else if (abs < 3600) label = `${Math.floor(abs / 60)}m`;
  else if (abs < 86400) label = `${Math.floor(abs / 3600)}h`;
  else label = `${Math.floor(abs / 86400)}d`;
  return future ? `in ${label}` : `${label} ago`;
}

export function formatLocal(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleString();
}
