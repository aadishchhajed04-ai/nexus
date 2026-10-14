import { useMemo } from "react";
import ReactFlow, { Background, type Edge, type Node } from "reactflow";
import "reactflow/dist/style.css";
import type { NexusEventRow } from "../api/client";

const NODE_STYLE = {
  background: "var(--color-surface-raised)",
  color: "var(--color-text)",
  border: "1px solid var(--color-border)",
  borderRadius: 8,
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  padding: "6px 10px",
};

/**
 * Builds a minimal star/mesh graph from an incident's linked events:
 * one node per distinct IP, one edge per (source_ip, destination_ip)
 * pair actually observed. No layout library beyond React Flow's own
 * positioning — this is meant to orient an analyst at a glance, not
 * to be a full topology diagram.
 */
export function NetworkGraph({ events }: { events: NexusEventRow[] }) {
  const { nodes, edges } = useMemo(() => {
    const ips = new Set<string>();
    const edgeKeys = new Set<string>();
    for (const e of events) {
      if (e.source_ip) ips.add(e.source_ip);
      if (e.destination_ip) ips.add(e.destination_ip);
      if (e.source_ip && e.destination_ip) {
        edgeKeys.add(`${e.source_ip}->${e.destination_ip}`);
      }
    }
    const ipList = Array.from(ips);
    const radius = 160;
    const cx = 220;
    const cy = 160;

    const nodes: Node[] = ipList.map((ip, i) => {
      const angle = (2 * Math.PI * i) / Math.max(ipList.length, 1);
      return {
        id: ip,
        data: { label: ip },
        position: { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) },
        style: NODE_STYLE,
      };
    });

    const edges: Edge[] = Array.from(edgeKeys).map((key) => {
      const [source, target] = key.split("->");
      return {
        id: key,
        source,
        target,
        style: { stroke: "var(--color-border)" },
        animated: false,
      };
    });

    return { nodes, edges };
  }, [events]);

  if (nodes.length === 0) {
    return <p className="text-sm text-[var(--color-text-faint)]">No IPs to graph yet.</p>;
  }

  return (
    <div className="h-[340px] rounded-[10px] border border-[var(--color-border)] bg-[var(--color-surface)]">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
        <Background color="var(--color-border-subtle)" gap={20} />
      </ReactFlow>
    </div>
  );
}
