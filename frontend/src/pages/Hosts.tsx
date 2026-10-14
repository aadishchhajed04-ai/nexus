import { api } from "../api/client";
import { usePoll } from "../hooks/usePoll";

export function Hosts() {
  const hosts = usePoll(api.getHosts, 5000);
  const services = usePoll(api.getServices, 5000);

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold">Hosts &amp; Services</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Everything discovered across all collectors, aggregated by destination.
        </p>
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-[var(--color-text-muted)]">Hosts</h2>
        <div className="overflow-hidden rounded-[10px] border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs text-[var(--color-text-muted)]">
                <th className="px-4 py-3 font-medium">IP</th>
                <th className="px-4 py-3 text-right font-medium">Events</th>
                <th className="px-4 py-3 text-right font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {hosts.data?.map((h) => (
                <tr
                  key={h.ip}
                  className="border-b border-[var(--color-border-subtle)] bg-[var(--color-surface)] last:border-0"
                >
                  <td className="mono px-4 py-2.5">{h.ip}</td>
                  <td className="mono px-4 py-2.5 text-right">{h.event_count}</td>
                  <td className="mono px-4 py-2.5 text-right text-xs text-[var(--color-text-faint)]">
                    {new Date(h.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {hosts.data && hosts.data.length === 0 && (
            <p className="bg-[var(--color-surface)] px-4 py-8 text-center text-sm text-[var(--color-text-faint)]">
              No hosts discovered yet.
            </p>
          )}
        </div>
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-[var(--color-text-muted)]">Services</h2>
        <div className="overflow-hidden rounded-[10px] border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs text-[var(--color-text-muted)]">
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Port</th>
                <th className="px-4 py-3 font-medium">Protocol</th>
                <th className="px-4 py-3 text-right font-medium">Events</th>
              </tr>
            </thead>
            <tbody>
              {services.data?.map((s, i) => (
                <tr
                  key={`${s.ip}-${s.port}-${i}`}
                  className="border-b border-[var(--color-border-subtle)] bg-[var(--color-surface)] last:border-0"
                >
                  <td className="mono px-4 py-2.5">{s.ip}</td>
                  <td className="mono px-4 py-2.5">{s.port}</td>
                  <td className="px-4 py-2.5 text-[var(--color-text-muted)]">{s.protocol}</td>
                  <td className="mono px-4 py-2.5 text-right">{s.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {services.data && services.data.length === 0 && (
            <p className="bg-[var(--color-surface)] px-4 py-8 text-center text-sm text-[var(--color-text-faint)]">
              No services discovered yet.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
