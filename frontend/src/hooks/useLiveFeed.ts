import { useEffect, useRef, useState } from "react";
import { wsUrl } from "../api/client";

export type LiveMessage =
  | { type: "event"; event: Record<string, unknown> }
  | {
      type: "incident_update";
      incident_id: number;
      title: string;
      risk_score: number;
      severity: string;
      breakdown: { label: string; weight: number }[];
    };

/**
 * Connects to the NEXUS WebSocket and keeps a short rolling log of
 * live messages plus a connection status flag. Reconnects with a
 * fixed backoff rather than failing silently — a dashboard that
 * quietly stops updating after one dropped connection is worse than
 * no live updates at all.
 */
export function useLiveFeed(onMessage?: (msg: LiveMessage) => void) {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<LiveMessage[]>([]);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;
    let cancelled = false;

    function connect() {
      socket = new WebSocket(wsUrl());
      socket.onopen = () => setConnected(true);
      socket.onclose = () => {
        setConnected(false);
        if (!cancelled) retryTimer = setTimeout(connect, 2000);
      };
      socket.onerror = () => socket?.close();
      socket.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as LiveMessage;
          setMessages((prev) => [msg, ...prev].slice(0, 50));
          onMessageRef.current?.(msg);
        } catch {
          // Ignore malformed frames rather than crash the dashboard.
        }
      };
    }
    connect();

    return () => {
      cancelled = true;
      clearTimeout(retryTimer);
      socket?.close();
    };
  }, []);

  return { connected, messages };
}
