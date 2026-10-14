import { Link } from "react-router-dom";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { api } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import { StatCard } from "../components/StatCard";
import { SeverityBadge } from "../components/SeverityBadge";

const SEVERITY_COLOR: Record<string, string> = {
  low: "#5fbe86",
  medium: "#e8b84b",
  high: "#e88a4b",
  critical: "#e85d5d",
};

export function Overview() {
  const stats = usePoll(api.getStatistics, 4000);
  const incidents = usePoll(() => api.getIncidents(50), 4000);

  const distribution = ["low", "medium", "high", "critical"].map((sev) => ({
    name: sev,
    value: incidents.data?.filter((i) => i.severity === sev).length ?? 0,
  }));
  const hasIncidents = distribution.some((d) => d.value > 0);

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold">Overview</h1>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">
          Live status across every connected collector.
        </p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total events" value={stats.data?.total_events ?? "—"} />
        <StatCard
          label="Active incidents"
          value={stats.data?.active_incidents ?? "—"}
          accent="var(--color-accent)"
        />
        <StatCard
          label="Critical incidents"
          value={stats.data?.critical_incidents ?? "—"}
          accent="#e85d5d"
        />
        <StatCard label="Total incidents" value={stats.data?.total_incidents ?? "—"} />
      </div>

      <div className="grid grid-cols-[1fr_260px] gap-6">
        <div className="rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-medium">Recent incidents</h2>
            <Link to="/incidents" className="text-xs text-[var(--color-accent)]">
              View all
            </Link>
          </div>
          {incidents.data && incidents.data.length > 0 ? (
            <ul className="flex flex-col divide-y divide-[var(--color-border-subtle)]">
              {incidents.data.slice(0, 6).map((inc) => (
                <li key={inc.incident_id} className="py-3">
                  <Link
                    to={`/incidents/${inc.incident_id}`}
                    className="flex items-center justify-between gap-4 hover:text-[var(--color-accent)]"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm">{inc.title}</div>
                      <div className="mono mt-0.5 text-xs text-[var(--color-text-faint)]">
                        INC-{String(inc.incident_id).padStart(4, "0")}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <span className="mono text-sm text-[var(--color-text-muted)]">
                        {inc.risk_score}
                      </span>
                      <SeverityBadge severity={inc.severity} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <p className="py-6 text-center text-sm text-[var(--color-text-faint)]">
              No incidents yet — waiting on collector activity.
            </p>
          )}
        </div>

        <div className="rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <h2 className="mb-2 text-sm font-medium">Severity mix</h2>
          {hasIncidents ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={3}
                  stroke="none"
                >
                  {distribution.map((d) => (
                    <Cell key={d.name} fill={SEVERITY_COLOR[d.name]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--color-surface-raised)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="py-10 text-center text-sm text-[var(--color-text-faint)]">
              Nothing scored yet.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
