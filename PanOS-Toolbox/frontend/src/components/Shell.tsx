import {
  Activity,
  AlertTriangle,
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
  UsersRound,
  X,
  Zap,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import type { ConnectionSession } from "../model";
import { shortId } from "../model";
import { Button, StatusPill } from "./Primitives";

export type ViewId = "connection" | "cleanup" | "plan" | "execute" | "warnings" | "ad-groups" | "policy-requests" | "audit" | "history" | "restore";

const navItems: Array<{ id: ViewId; label: string; description: string; icon: typeof Network }> = [
  { id: "connection", label: "Połączenie", description: "Panorama i Doctor", icon: LayoutDashboard },
  { id: "cleanup", label: "Cleanup", description: "Szukaj punktowo lub batch", icon: ListChecks },
  { id: "plan", label: "Plan", description: "Operacje pojedynczo", icon: ClipboardCheck },
  { id: "execute", label: "Wykonaj", description: "Candidate · Commit · Push", icon: Zap },
  { id: "ad-groups", label: "Grupy AD", description: "Custom LDAP Group", icon: UsersRound },
  { id: "policy-requests", label: "Nowe polityki", description: "Wklejka → API plan", icon: Network },
  { id: "audit", label: "Audit", description: "Pozostałe referencje", icon: SearchCheck },
  { id: "history", label: "Backup i restore", description: "Sesje i joby", icon: History },
  { id: "restore", label: "Emergency Restore", description: "Bezpieczne odtworzenie", icon: RefreshCcw },
  { id: "warnings", label: "Uwagi", description: "Analiza i blokady", icon: AlertTriangle },
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
  warningCount: number;
  children: ReactNode;
}

export function Shell({ activeView, onViewChange, connection, writeEnabled, onWriteEnabledChange, theme, onThemeChange, onDisconnect, demoMode, warningCount, children }: ShellProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [confirmingWrite, setConfirmingWrite] = useState(false);

  const navigate = (view: ViewId) => {
    onViewChange(view);
    setMobileOpen(false);
  };

  const requestWrite = (enabled: boolean) => {
    if (!enabled) {
      onWriteEnabledChange(false);
      setConfirmingWrite(false);
      return;
    }
    if (connection) setConfirmingWrite(true);
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "sidebar--open" : ""}`}>
        <div className="brand">
          <div className="bytetech-brand" title="ByteTech">
            <span className="brand__mark"><b>BT</b></span>
            <span className="brand__copy"><strong>ByteTech</strong><small>PanOS Toolbox</small></span>
          </div>
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
          ) : <span>Historia i backupy działają offline. Połącz się dopiero do operacji live.</span>}
        </div>

        <nav className="main-nav" aria-label="Główna nawigacja">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={activeView === item.id ? "is-active" : ""} onClick={() => navigate(item.id)}>
                <Icon size={19} aria-hidden="true" />
                <span><strong>{item.label}</strong><small>{item.description}</small></span>
                {item.id === "warnings" && warningCount > 0 && <b className="nav-warning-badge" aria-label={`${warningCount} uwag`}>{warningCount > 99 ? "99+" : warningCount}</b>}
              </button>
            );
          })}
        </nav>

        <div className="sidebar__footer">
          <div className="safety-note"><ShieldCheck size={17} /><span>API i GUI dostępne wyłącznie na localhost.</span></div>
          <div className="paloalto-brand"><span>Built for</span><img src="/paloalto-logo-light.png" alt="Palo Alto Networks" /><small>{connection ? `PAN-OS ${connection.panoramaVersion}` : "Panorama XML API"}</small></div>
          <span>Open source · ByteTech · v0.8.2</span>
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
            <span title="Status niezacommitowanych zmian odczytany z Panorama change-summary">
              <StatusPill tone={!connection ? "neutral" : connection.candidateStatus === "dirty" ? "warning" : connection.candidateStatus === "clean" ? "success" : "info"}>
                {!connection ? "Offline" : connection.candidateStatus === "dirty" ? "Candidate: są niezacommitowane zmiany" : connection.candidateStatus === "clean" ? "Candidate: bez zmian" : "Candidate: status nieznany"}
              </StatusPill>
            </span>
            <button className="icon-button" onClick={onThemeChange} aria-label={theme === "dark" ? "Włącz jasny motyw" : "Włącz ciemny motyw"}>
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            {connection && <Button variant="ghost" icon={<Unplug size={16} />} onClick={onDisconnect}>Rozłącz</Button>}
          </div>
        </header>

        <div className={`write-gate ${writeEnabled ? "write-gate--enabled" : ""}`}>
          <div>
            <Zap size={17} />
            <span><strong>{writeEnabled ? "WRITE" : "READ ONLY"}</strong>{writeEnabled ? " · realne operacje XML API są dozwolone" : " · wyszukiwanie, analiza i backup bez zmian w Panorama"}</span>
          </div>
          <label className="compact-switch">
            <span>{writeEnabled ? "WRITE" : "READ ONLY"}</span>
            <input type="checkbox" checked={writeEnabled} onChange={(event) => requestWrite(event.target.checked)} disabled={!connection} aria-label="Przełącz READ ONLY / WRITE" />
            <i aria-hidden="true" />
          </label>
        </div>

        <main className="page-content">{children}</main>
      </div>

      {confirmingWrite && connection && (
        <div className="write-confirm-backdrop" role="presentation">
          <div className="write-confirm" role="dialog" aria-modal="true" aria-labelledby="write-confirm-title">
            <div><AlertTriangle size={21} /><strong id="write-confirm-title">Czy na pewno chcesz włączyć WRITE?</strong></div>
            <p>Toolbox zezwoli na realne, ścieżkowe operacje XML API na <code>{connection.host}</code> jako <code>{connection.username}</code>. Każda encja ma backup; Candidate, commit i push pozostają trzema osobnymi etapami.</p>
            <div><Button onClick={() => setConfirmingWrite(false)}>Anuluj</Button><Button variant="primary" onClick={() => { onWriteEnabledChange(true); setConfirmingWrite(false); }}>Tak, włącz WRITE</Button></div>
          </div>
        </div>
      )}
    </div>
  );
}
