import type { ReactNode } from "react";

function inline(text: string): ReactNode {
  // Handles the few inline forms the report generator actually emits:
  // `code`, **bold**. Anything else passes through as plain text.
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean);
  return parts.map((part, i) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={i}
          className="mono rounded bg-[var(--color-surface-raised)] px-1 py-0.5 text-[13px]"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    return part;
  });
}

export function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];

  lines.forEach((line, i) => {
    if (line.startsWith("# ")) {
      blocks.push(
        <h1 key={i} className="mt-2 text-lg font-semibold">
          {inline(line.slice(2))}
        </h1>
      );
    } else if (line.startsWith("## ")) {
      blocks.push(
        <h2 key={i} className="mt-6 text-sm font-semibold text-[var(--color-accent)]">
          {inline(line.slice(3))}
        </h2>
      );
    } else if (line.startsWith("### ")) {
      blocks.push(
        <h3 key={i} className="mt-4 text-sm font-medium">
          {inline(line.slice(4))}
        </h3>
      );
    } else if (line.startsWith("> ")) {
      blocks.push(
        <p key={i} className="mt-2 border-l-2 border-[var(--color-border)] pl-3 text-xs text-[var(--color-text-faint)]">
          {inline(line.slice(2))}
        </p>
      );
    } else if (line.startsWith("- ")) {
      blocks.push(
        <li key={i} className="ml-4 list-disc text-sm text-[var(--color-text-muted)]">
          {inline(line.slice(2))}
        </li>
      );
    } else if (line.trim() === "") {
      blocks.push(<div key={i} className="h-2" />);
    } else {
      blocks.push(
        <p key={i} className="text-sm text-[var(--color-text)]">
          {inline(line)}
        </p>
      );
    }
  });

  return <div className="flex flex-col gap-0.5">{blocks}</div>;
}
