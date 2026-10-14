import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Incident } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import { SeverityBadge } from "../components/SeverityBadge";
import { RiskBreakdown } from "../components/RiskBreakdown";
import { Timeline } from "../components/Timeline";
import { NetworkGraph } from "../components/NetworkGraph";
import { Markdown } from "../components/Markdown";

const TABS = ["Timeline", "Network", "Report"] as const;
type Tab = (typeof TABS)[number];

const STATUS_OPTIONS: Incident["status"][] = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];

function StatusControl({
  current,
  updating,
  onChange,
}: {
  current: Incident["status"];
  updating: boolean;
  onChange: (status: Incident["status"]) => void;
}) {
  return (
    <select
      value={current}
      disabled={updating}
      onChange={(e) => onChange(e.target.value as Incident["status"])}
      className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2.5 py-1 text-xs text-[var(--color-text)] disabled:opacity-50"
    >
      {STATUS_OPTIONS.map((s) => (
        <option key={s} value={s}>
          {s}
        </option>
      ))}
    </select>
  );
}

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const incidentId = Number(id);
  const [tab, setTab] = useState<Tab>("Timeline");
  const [updating, setUpdating] = useState(false);

  const incident = usePoll(() => api.getIncident(incidentId), 5000);
  const risk = usePoll(() => api.getIncidentRisk(incidentId), 5000);
  const timeline = usePoll(() => api.getTimeline(incidentId), 5000);
  const report = usePoll(() => api.getReport(incidentId), 0); // fetched once, tab is static text

  async function changeStatus(status: Incident["status"]) {
    setUpdating(true);
    try {
      await api.setIncidentStatus(incidentId, status);
      incident.refresh();
    } finally {
      setUpdating(false);
    }
  }

  if (!incident.data) {
    return <p className="text-sm text-[var(--color-text-faint)]">Loading…</p>;
  }
  const inc = incident.data;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link to="/incidents" className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-accent)]">
          ← Incidents
        </Link>
        <div className="mt-2 flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold">{inc.title}</h1>
            <div className="mono mt-1 text-xs text-[var(--color-text-faint)]">
              INC-{String(inc.incident_id).padStart(4, "0")} · created{" "}
              {new Date(inc.created_at).toLocaleString()}
            </div>
          </div>
          <SeverityBadge severity={inc.severity} />
        </div>
        <div className="mt-4 flex items-center gap-2">
          <span className="text-xs text-[var(--color-text-muted)]">Status:</span>
          <StatusControl current={inc.status} updating={updating} onChange={changeStatus} />
        </div>
        {inc.description && (
          <p className="mt-3 max-w-[70ch] text-sm text-[var(--color-text-muted)]">{inc.description}</p>
        )}
      </div>

      <div className="grid grid-cols-[1fr_320px] gap-6">
        <div>
          <div className="mb-4 flex gap-1 border-b border-[var(--color-border)]">
            {TABS.map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-3 py-2 text-sm transition-colors ${
                  tab === t
                    ? "border-b-2 border-[var(--color-accent)] text-[var(--color-accent)]"
                    : "text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {tab === "Timeline" && (
            <div className="rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
              <Timeline events={timeline.data ?? []} />
            </div>
          )}

          {tab === "Network" && <NetworkGraph events={timeline.data ?? []} />}

          {tab === "Report" && (
            <div className="rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
              {report.data ? (
                <Markdown text={report.data.markdown} />
              ) : (
                <p className="text-sm text-[var(--color-text-faint)]">Generating…</p>
              )}
            </div>
          )}
        </div>

        <div className="flex flex-col gap-4">
          {risk.data && (
            <RiskBreakdown
              score={risk.data.score}
              severity={risk.data.severity}
              breakdown={risk.data.breakdown}
            />
          )}
        </div>
      </div>
    </div>
  );
}
