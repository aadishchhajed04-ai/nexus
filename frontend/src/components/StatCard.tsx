export function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div className="rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-4">
      <div className="text-sm text-[var(--color-text-muted)]">{label}</div>
      <div
        className="mt-1.5 text-[28px] font-semibold leading-none"
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
    </div>
  );
}
