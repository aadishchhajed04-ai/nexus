import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import App from "../App";

/**
 * These don't touch a real backend or a real browser — no Playwright/
 * Chromium available in this build environment (its CDN isn't on the
 * sandbox's allowed network list). What this DOES prove, which `tsc`
 * alone does not: every page actually mounts, every hook runs, and
 * nothing throws at render time when fed realistic API responses —
 * the class of bug that only shows up live in a real browser.
 */

const SAMPLE_INCIDENT = {
  incident_id: 1,
  created_at: "2026-09-24T10:00:00Z",
  updated_at: "2026-09-24T10:05:00Z",
  title: "Possible Network Reconnaissance — 10.0.0.5",
  description: "Auto-created from a 'port_scan' detection involving 10.0.0.5.",
  risk_score: 35,
  severity: "medium" as const,
  status: "OPEN" as const,
};

const SAMPLE_EVENT = {
  event_id: "abc123ef-0000-0000-0000-000000000000",
  timestamp: "2026-09-24T10:00:00Z",
  source: "nmap",
  event_type: "service_discovery",
  source_ip: "10.0.0.5",
  destination_ip: "10.0.0.20",
  source_port: null,
  destination_port: 22,
  protocol: "tcp",
  severity: "low" as const,
  confidence: 0.9,
  raw_data: "{}",
};

function jsonResponse(body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
}

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/statistics")) {
        return jsonResponse({ total_events: 42, active_incidents: 1, critical_incidents: 0, total_incidents: 1 });
      }
      if (url.includes("/incidents/1/risk")) {
        return jsonResponse({ score: 35, severity: "medium", breakdown: [{ label: "Port scan", weight: 20 }] });
      }
      if (url.includes("/incidents/1/status")) {
        return jsonResponse({ incident_id: 1, status: "INVESTIGATING" });
      }
      if (url.match(/\/incidents\/1$/)) {
        return jsonResponse(SAMPLE_INCIDENT);
      }
      if (url.includes("/incidents")) {
        return jsonResponse([SAMPLE_INCIDENT]);
      }
      if (url.includes("/timeline/1")) {
        return jsonResponse([SAMPLE_EVENT]);
      }
      if (url.includes("/reports/1")) {
        return jsonResponse({ markdown: "# Incident Report — INC-0001\n\n**Risk score:** 35 (MEDIUM)" });
      }
      if (url.includes("/events")) {
        return jsonResponse([SAMPLE_EVENT]);
      }
      if (url.includes("/hosts")) {
        return jsonResponse([{ ip: "10.0.0.20", event_count: 3, last_seen: "2026-09-24T10:00:00Z" }]);
      }
      if (url.includes("/services")) {
        return jsonResponse([{ ip: "10.0.0.20", port: 22, protocol: "tcp", event_count: 3 }]);
      }
      return jsonResponse({});
    })
  );

  // Real WebSocket would try an actual network connection under jsdom.
  // A no-op stub keeps useLiveFeed's effect from throwing or hanging.
  class FakeWebSocket {
    onopen: (() => void) | null = null;
    onclose: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onmessage: ((ev: MessageEvent) => void) | null = null;
    close() {}
    send() {}
  }
  vi.stubGlobal("WebSocket", FakeWebSocket);

  // jsdom has no ResizeObserver; React Flow needs one to measure its
  // canvas. Real browsers all have this natively.
  class FakeResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  vi.stubGlobal("ResizeObserver", FakeResizeObserver);
});

describe("NEXUS dashboard smoke tests", () => {
  it("renders Overview without throwing", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeTruthy();
    expect(await screen.findByText(/Active incidents/i)).toBeTruthy();
  });

  it("navigates to Incidents and lists the sample incident", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("link", { name: "Incidents" }));
    expect(await screen.findByText(/Network Reconnaissance/i)).toBeTruthy();
  });

  it("opens an incident and renders timeline, risk breakdown, and status control", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("link", { name: "Incidents" }));
    fireEvent.click(await screen.findByText(/Network Reconnaissance/i));

    expect(await screen.findByText("Port scan")).toBeTruthy(); // risk breakdown factor
    expect(await screen.findByDisplayValue("OPEN")).toBeTruthy(); // status <select>

    // Switch to the Network tab and confirm the graph mounts without error.
    fireEvent.click(await screen.findByText("Network"));
    await waitFor(() => expect(document.querySelector(".react-flow")).toBeTruthy());

    // Switch to the Report tab and confirm the markdown renders.
    fireEvent.click(await screen.findByText("Report"));
    expect((await screen.findAllByText(/INC-0001/)).length).toBeGreaterThan(0);
  });

  it("changing incident status calls the API", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("link", { name: "Incidents" }));
    fireEvent.click(await screen.findByText(/Network Reconnaissance/i));

    const select = await screen.findByDisplayValue("OPEN");
    fireEvent.change(select, { target: { value: "INVESTIGATING" } });

    await waitFor(() => {
      const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls.some((c) => String(c[0]).includes("/incidents/1/status"))).toBe(true);
    });
  });

  it("renders Events and Hosts pages without throwing", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("link", { name: "Events" }));
    expect(await screen.findByText("service_discovery")).toBeTruthy();

    fireEvent.click(await screen.findByRole("link", { name: "Hosts & Services" }));
    expect((await screen.findAllByText("10.0.0.20")).length).toBeGreaterThan(0);
  });
});
