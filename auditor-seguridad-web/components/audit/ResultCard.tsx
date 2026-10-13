import type { LucideIcon } from "lucide-react";
import { StatusBadge } from "./StatusBadge";

export type FindingStatus = "ok" | "warn" | "missing";

export type Finding = {
  label: string;
  value: string;
  status: FindingStatus;
};

type ResultCardProps = {
  title: string;
  subtitle: string;
  icon: LucideIcon;
  findings: Finding[];
};

export function ResultCard({
  title,
  subtitle,
  icon: Icon,
  findings,
}: ResultCardProps) {
  return (
    <article className="flex flex-col border border-crimson-800/40 bg-ink-800/80 shadow-panel backdrop-blur-sm">
      <header className="flex items-start gap-3 border-b border-steel-600/30 bg-ink-900/70 px-5 py-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center border border-crimson-600/50 bg-crimson-800/30 text-crimson-400">
          <Icon className="h-5 w-5" aria-hidden />
        </div>
        <div>
          <h2 className="font-[family-name:var(--font-geist-mono)] text-sm uppercase tracking-[0.28em] text-steel-300">
            {title}
          </h2>
          <p className="mt-1 text-xs text-steel-400">{subtitle}</p>
        </div>
      </header>
      <ul className="divide-y divide-ink-700">
        {findings.map((finding) => (
          <li
            key={finding.label}
            className="flex flex-col gap-2 px-5 py-3.5 sm:flex-row sm:items-start sm:justify-between"
          >
            <div className="min-w-0">
              <p className="font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-wider text-steel-400">
                {finding.label}
              </p>
              <p className="mt-1 break-all text-sm text-foreground/90">
                {finding.value}
              </p>
            </div>
            <StatusBadge status={finding.status} />
          </li>
        ))}
      </ul>
    </article>
  );
}
