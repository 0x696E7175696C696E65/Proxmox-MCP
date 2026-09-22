export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
      <div
        className="size-5 animate-spin rounded-full border-2 border-muted-foreground/25 border-t-primary"
        aria-hidden
      />
      <p className="text-xs">{label}</p>
    </div>
  );
}
