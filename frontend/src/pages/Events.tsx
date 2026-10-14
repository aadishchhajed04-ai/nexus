import { useMemo, useState } from "react";
import { api } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import { SeverityBadge } from "../components/SeverityBadge";

const SOURCES = ["all", "nmap", "scapy", "wireshark", "burp", "linux", "capa", "detection"];

export function Events() {
  const events = usePoll(() => api.getEvents(300), 4000);
  const [source, setSource] = useState("all");

  const filtered = useMemo(
    () => (events.data ?? []).filter((e) => source === "all" || e.source === source),
    [events.data, source]
  );

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Events</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Every event received from a collector or produced by detection, most recent first.
        </p>
      </div>

      <div className="flex gap-1.5">
        {SOURCES.map((s) => (
          <button
            key={s}
            onClick={() => setSource(s)}
            className={`rounded-full px-3 py-1 text-xs transition-colors ${
              source === s
                ? "bg-[var(--color-accent-soft)] text-[var(--color-accent)]"
                : "text-[var(--color-text-muted)] hover:bg-white/[0.03]"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="overflow-hidden rounded-[10px] border border-[var(--color-border)]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs text-[var(--color-text-muted)]">
              <th className="px-4 py-3 font-medium">Time</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Flow</th>
              <th className="px-4 py-3 font-medium">Severity</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr
                key={e.event_id}
                className="border-b border-[var(--color-border-subtle)] bg-[var(--color-surface)] last:border-0"
              >
                <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-faint)]">
                  {new Date(e.timestamp).toLocaleTimeString()}
                </td>
                <td className="px-4 py-2.5">{e.event_type}</td>
                <td className="px-4 py-2.5 text-[var(--color-text-muted)]">{e.source}</td>
                <td className="mono px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
                  {e.source_ip ? `${e.source_ip}${e.source_port ? ":" + e.source_port : ""}` : "—"}
                  {e.destination_ip ? ` → ${e.destination_ip}${e.destination_port ? ":" + e.destination_port : ""}` : ""}
                </td>
                <td className="px-4 py-2.5">
                  <SeverityBadge severity={e.severity} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p className="bg-[var(--color-surface)] px-4 py-10 text-center text-sm text-[var(--color-text-faint)]">
            No events for this filter yet.
          </p>
        )}
      </div>
    </div>
  );
}
