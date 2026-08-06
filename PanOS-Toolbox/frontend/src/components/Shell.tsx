import {
  Activity,
  ClipboardCheck,
  History,
  LayoutDashboard,
  ListChecks,
  Menu,
  Moon,
  Network,
  RefreshCcw,
  SearchCheck,
  ShieldCheck,
  Sun,
  Unplug,
  X,
  Zap,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import type { ConnectionSession } from "../model";
import { shortId } from "../model";
import { Button, StatusPill } from "./Primitives";

export type ViewId = "connection" | "cleanup" | "plan" | "audit" | "history" | "restore";

const navItems: Array<{ id: ViewId; label: string; description: string; icon: typeof Network }> = [
  { id: "connection", label: "Połączenie", description: "Panorama i Doctor", icon: LayoutDashboard },
  { id: "cleanup", label: "Cleanup", description: "Adresy i analiza", icon: ListChecks },
  { id: "plan", label: "Plan i wykonanie", description: "Candidate · Commit · Push", icon: ClipboardCheck },
  { id: "audit", label: "Audit", description: "Pozostałe referencje", icon: SearchCheck },
  { id: "history", label: "Historia", description: "Sesje i joby", icon: History },
  { id: "restore", label: "Emergency Restore", description: "Bezpieczne odtworzenie", icon: RefreshCcw },
];

interface ShellProps {
  activeView: ViewId;
  onViewChange: (view: ViewId) => void;
  connection: ConnectionSession | null;
  writeEnabled: boolean;
  onWriteEnabledChange: (enabled: boolean) => void;
  theme: "light" | "dark";
  onThemeChange: () => void;
  onDisconnect: () => void;
  demoMode: boolean;
  children: ReactNode;
}

export function Shell({ activeView, onViewChange, connection, writeEnabled, onWriteEnabledChange, theme, onThemeChange, onDisconnect, demoMode, children }: ShellProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const navigate = (view: ViewId) => {
    onViewChange(view);
    setMobileOpen(false);
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "sidebar--open" : ""}`}>
        <div className="brand">
          <div className="brand__mark"><Network size={22} strokeWidth={2.2} /></div>
          <div><strong>PanOS</strong><span>Toolbox</span></div>
          <button className="sidebar__close" onClick={() => setMobileOpen(false)} aria-label="Zamknij nawigację"><X size={20} /></button>
        </div>

        <div className="environment-card">
          <div className="environment-card__top">
            <span className={`pulse-dot ${connection ? "pulse-dot--online" : ""}`} />
            <strong>{connection ? connection.host : "Brak połączenia"}</strong>
          </div>
          {connection ? (
            <>
              <span>PAN-OS {connection.panoramaVersion}</span>
              <small>{connection.username} · {shortId(connection.id)}</small>
            </>
          ) : <span>Połącz się z Panorama, aby rozpocząć.</span>}
        </div>

        <nav className="main-nav" aria-label="Główna nawigacja">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={activeView === item.id ? "is-active" : ""} onClick={() => navigate(item.id)}>
                <Icon size={19} aria-hidden="true" />
                <span><strong>{item.label}</strong><small>{item.description}</small></span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar__footer">
          <div className="safety-note"><ShieldCheck size={17} /><span>API i GUI dostępne wyłącznie na localhost.</span></div>
          <span>PanOS Toolbox · lokalnie</span>
          <strong className="author-brand">Szymon Żołnierczyk · Devops Engineer NET</strong>
        </div>
      </aside>

      {mobileOpen && <button className="sidebar-backdrop" onClick={() => setMobileOpen(false)} aria-label="Zamknij nawigację" />}

      <div className="app-main">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Otwórz nawigację"><Menu size={20} /></button>
          <div className="topbar__context">
            <Activity size={16} />
            <span>Control plane</span>
            <span className="context-separator">/</span>
            <strong>{navItems.find((item) => item.id === activeView)?.label}</strong>
          </div>
          <div className="topbar__actions">
            {demoMode && <StatusPill tone="info">Tryb demo</StatusPill>}
            <StatusPill tone={!connection ? "neutral" : connection.candidateDirty ? "warning" : "success"}>
              {!connection ? "Offline" : connection.candidateDirty ? "Candidate dirty" : "Candidate clean"}
            </StatusPill>
            <button className="icon-button" onClick={onThemeChange} aria-label={theme === "dark" ? "Włącz jasny motyw" : "Włącz ciemny motyw"}>
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            {connection && <Button variant="ghost" icon={<Unplug size={16} />} onClick={onDisconnect}>Rozłącz</Button>}
          </div>
        </header>

        <div className={`write-gate ${writeEnabled ? "write-gate--enabled" : ""}`}>
          <div>
            <Zap size={17} />
            <span><strong>Zapis API</strong>{writeEnabled ? " aktywny dla tej sesji przeglądarki" : " wyłączony — generator/read-only"}</span>
          </div>
          <label className="compact-switch">
            <span>{writeEnabled ? "ON" : "OFF"}</span>
            <input
              type="checkbox"
              checked={writeEnabled}
              onChange={(event) => onWriteEnabledChange(event.target.checked)}
              disabled={!connection}
              aria-label="Włącz zapis przez API"
            />
            <i aria-hidden="true" />
          </label>
        </div>

        <main className="page-content">{children}</main>
      </div>
    </div>
  );
}
