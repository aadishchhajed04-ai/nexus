import type { NexusEventRow } from "../api/client";

const DOT_COLOR: Record<string, string> = {
  low: "var(--color-risk-low)",
  medium: "var(--color-risk-medium)",
  high: "var(--color-risk-high)",
  critical: "var(--color-risk-critical)",
};

function formatTime(iso: string) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function Timeline({ events }: { events: NexusEventRow[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-[var(--color-text-faint)]">No linked events yet.</p>;
  }

  return (
    <ol className="relative flex flex-col gap-5 pl-5">
      <div
        className="absolute left-[5px] top-2 bottom-2 w-px"
        style={{ background: "var(--color-border)" }}
      />
      {events.map((e) => (
        <li key={e.event_id} className="relative">
          <span
            className="absolute -left-5 top-1.5 h-2.5 w-2.5 rounded-full"
            style={{
              background: DOT_COLOR[e.severity] ?? "var(--color-text-faint)",
              boxShadow: "0 0 0 4px var(--color-bg)",
            }}
          />
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="mono text-xs text-[var(--color-text-faint)]">
              {formatTime(e.timestamp)}
            </span>
            <span className="text-sm font-medium">{e.event_type}</span>
            <span className="text-xs text-[var(--color-text-muted)]">via {e.source}</span>
          </div>
          {(e.source_ip || e.destination_ip) && (
            <div className="mono mt-0.5 text-xs text-[var(--color-text-muted)]">
              {e.source_ip ?? "?"}
              {e.source_port ? `:${e.source_port}` : ""} →{" "}
              {e.destination_ip ?? "?"}
              {e.destination_port ? `:${e.destination_port}` : ""}
            </div>
          )}
        </li>
      ))}
    </ol>
  );
}
