type Status = "ok" | "warn" | "missing";

const styles: Record<Status, string> = {
  ok: "border-steel-400/40 bg-steel-600/30 text-steel-300",
  warn: "border-amber-500/40 bg-amber-950/50 text-amber-300",
  missing: "border-crimson-500/40 bg-crimson-800/40 text-crimson-400",
};

const labels: Record<Status, string> = {
  ok: "Presente",
  warn: "Revisar",
  missing: "Ausente",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={`inline-flex items-center rounded-sm border px-2 py-0.5 font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-[0.18em] ${styles[status]}`}
    >
      {labels[status]}
    </span>
  );
}
