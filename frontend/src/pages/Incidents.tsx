import { Link } from "react-router-dom";
import { api } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import { SeverityBadge } from "../components/SeverityBadge";

export function Incidents() {
  const incidents = usePoll(() => api.getIncidents(200), 4000);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Incidents</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Every correlated group of events, ranked by risk score.
        </p>
      </div>

      <div className="overflow-hidden rounded-[10px] border border-[var(--color-border)]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)] text-left text-xs text-[var(--color-text-muted)]">
              <th className="px-4 py-3 font-medium">Incident</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 text-right font-medium">Risk</th>
              <th className="px-4 py-3 text-right font-medium">Updated</th>
            </tr>
          </thead>
          <tbody>
            {incidents.data?.map((inc) => (
              <tr
                key={inc.incident_id}
                className="border-b border-[var(--color-border-subtle)] bg-[var(--color-surface)] last:border-0 hover:bg-[var(--color-surface-raised)]"
              >
                <td className="px-4 py-3">
                  <Link to={`/incidents/${inc.incident_id}`} className="hover:text-[var(--color-accent)]">
                    <div>{inc.title}</div>
                    <div className="mono mt-0.5 text-xs text-[var(--color-text-faint)]">
                      INC-{String(inc.incident_id).padStart(4, "0")}
                    </div>
                  </Link>
                </td>
                <td className="px-4 py-3 text-[var(--color-text-muted)]">{inc.status}</td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={inc.severity} />
                </td>
                <td className="mono px-4 py-3 text-right">{inc.risk_score}</td>
                <td className="mono px-4 py-3 text-right text-xs text-[var(--color-text-faint)]">
                  {new Date(inc.updated_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {incidents.data && incidents.data.length === 0 && (
          <p className="bg-[var(--color-surface)] px-4 py-10 text-center text-sm text-[var(--color-text-faint)]">
            No incidents yet.
          </p>
        )}
      </div>
    </div>
  );
}
