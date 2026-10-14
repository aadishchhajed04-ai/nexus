const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const API_TOKEN = import.meta.env.VITE_API_TOKEN ?? "dev-token-change-me";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${API_TOKEN}`,
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json() as Promise<T>;
}

export interface NexusEventRow {
  event_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  raw_data: string;
}

export interface Incident {
  incident_id: number;
  created_at: string;
  updated_at: string;
  title: string;
  description: string;
  risk_score: number;
  severity: "low" | "medium" | "high" | "critical";
  status: "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
}

export interface Statistics {
  total_events: number;
  active_incidents: number;
  critical_incidents: number;
  total_incidents: number;
}

export interface RiskBreakdownResponse {
  score: number;
  severity: string;
  breakdown: { label: string; weight: number }[];
}

export const api = {
  getEvents: (limit = 100) => request<NexusEventRow[]>(`/events?limit=${limit}`),
  getIncidents: (limit = 100) => request<Incident[]>(`/incidents?limit=${limit}`),
  getIncident: (id: number) => request<Incident>(`/incidents/${id}`),
  getIncidentRisk: (id: number) => request<RiskBreakdownResponse>(`/incidents/${id}/risk`),
  getTimeline: (id: number) => request<NexusEventRow[]>(`/timeline/${id}`),
  getStatistics: () => request<Statistics>("/statistics"),
  getHosts: () => request<{ ip: string; event_count: number; last_seen: string }[]>("/hosts"),
  getServices: () =>
    request<{ ip: string; port: number; protocol: string; event_count: number }[]>("/services"),
  getReport: (id: number) => request<{ markdown: string }>(`/reports/${id}`),
  setIncidentStatus: (id: number, status: Incident["status"]) =>
    request(`/incidents/${id}/status?status=${status}`, { method: "POST" }),
};

export function wsUrl(): string {
  const url = new URL(BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws";
  return url.toString();
}
