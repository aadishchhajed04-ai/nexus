import { NavLink, Outlet } from "react-router-dom";
import { useLiveFeed } from "../../hooks/useLiveFeed";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/incidents", label: "Incidents" },
  { to: "/events", label: "Events" },
  { to: "/hosts", label: "Hosts & Services" },
];

export function AppShell() {
  const { connected } = useLiveFeed();

  return (
    <div className="flex h-full">
      <aside className="flex w-[220px] shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-5">
        <div className="mb-8 flex items-center gap-2 px-1">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <circle cx="4" cy="4" r="2" fill="var(--color-accent)" />
            <circle cx="16" cy="4" r="2" fill="var(--color-accent)" />
            <circle cx="10" cy="16" r="2" fill="var(--color-accent)" />
            <path
              d="M4 4L16 4M4 4L10 16M16 4L10 16"
              stroke="var(--color-border)"
              strokeWidth="1"
            />
          </svg>
          <span className="text-[15px] font-semibold tracking-tight">NEXUS</span>
        </div>

        <nav className="flex flex-col gap-0.5">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-[var(--color-accent-soft)] font-medium text-[var(--color-accent)]"
                    : "text-[var(--color-text-muted)] hover:bg-white/[0.03] hover:text-[var(--color-text)]"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex items-center gap-2 px-3 py-2 text-xs text-[var(--color-text-faint)]">
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: connected ? "var(--color-risk-low)" : "var(--color-risk-critical)" }}
          />
          {connected ? "Live" : "Reconnecting…"}
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1100px] px-8 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
