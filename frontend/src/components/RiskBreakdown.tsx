const SEVERITY_COLOR: Record<string, string> = {
  low: "var(--color-risk-low)",
  medium: "var(--color-risk-medium)",
  high: "var(--color-risk-high)",
  critical: "var(--color-risk-critical)",
};

export function RiskBreakdown({
  score,
  severity,
  breakdown,
}: {
  score: number;
  severity: string;
  breakdown: { label: string; weight: number }[];
}) {
  const color = SEVERITY_COLOR[severity] ?? "var(--color-text-muted)";
  return (
    <div className="rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-baseline justify-between">
        <span className="text-sm text-[var(--color-text-muted)]">Risk score</span>
        <span className="text-xs text-[var(--color-text-faint)]">
          not a calibrated probability — prioritization aid only
        </span>
      </div>
      <div className="mt-2 flex items-end gap-3">
        <span className="text-[40px] font-semibold leading-none" style={{ color }}>
          {score}
        </span>
        <span className="mb-1 text-sm text-[var(--color-text-muted)]">/ 100</span>
      </div>

      <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-border)]">
        <div
          className="h-full rounded-full transition-[width]"
          style={{ width: `${Math.min(score, 100)}%`, background: color }}
        />
      </div>

      {breakdown.length > 0 ? (
        <ul className="mt-5 flex flex-col gap-2.5">
          {breakdown.map((factor) => (
            <li key={factor.label} className="flex items-center justify-between text-sm">
              <span className="text-[var(--color-text)]">{factor.label}</span>
              <span className="mono text-[var(--color-text-muted)]">+{factor.weight}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-5 text-sm text-[var(--color-text-faint)]">
          No scored factors linked to this incident yet.
        </p>
      )}
    </div>
  );
}
