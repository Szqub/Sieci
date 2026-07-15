import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, LoaderCircle, ShieldAlert, XCircle } from "lucide-react";
import type { Severity } from "../model";

export type Tone = "neutral" | "accent" | "success" | "warning" | "danger" | "info";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  loading?: boolean;
  icon?: ReactNode;
}

export function Button({ variant = "secondary", loading, icon, children, className = "", disabled, ...props }: ButtonProps) {
  return (
    <button className={`button button--${variant} ${className}`} disabled={disabled || loading} {...props}>
      {loading ? <LoaderCircle className="spin" size={17} aria-hidden="true" /> : icon}
      <span>{children}</span>
    </button>
  );
}

export function StatusPill({ tone = "neutral", children, dot = true }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  return (
    <span className={`status-pill status-pill--${tone}`}>
      {dot && <span className="status-pill__dot" aria-hidden="true" />}
      {children}
    </span>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </header>
  );
}

export function Card({ children, className = "", ...props }: HTMLAttributes<HTMLDivElement>) {
  return <section className={`card ${className}`} {...props}>{children}</section>;
}

export function CardHeader({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="card-header">
      <div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}

const alertIcons = {
  info: Info,
  warning: AlertTriangle,
  danger: ShieldAlert,
  success: CheckCircle2,
} satisfies Record<Severity, typeof Info>;

export function Callout({ severity = "info", title, children, actions }: { severity?: Severity; title: string; children: ReactNode; actions?: ReactNode }) {
  const Icon = alertIcons[severity];
  return (
    <div className={`callout callout--${severity}`} role={severity === "danger" ? "alert" : "status"}>
      <Icon size={19} aria-hidden="true" />
      <div className="callout__content">
        <strong>{title}</strong>
        <div>{children}</div>
      </div>
      {actions && <div className="callout__actions">{actions}</div>}
    </div>
  );
}

export function Toggle({ checked, onChange, label, description, danger = false, disabled = false }: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  description?: string;
  danger?: boolean;
  disabled?: boolean;
}) {
  return (
    <label className={`toggle-row ${danger ? "toggle-row--danger" : ""} ${disabled ? "is-disabled" : ""}`}>
      <span className="toggle-copy">
        <strong>{label}</strong>
        {description && <span>{description}</span>}
      </span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} disabled={disabled} />
      <span className="toggle" aria-hidden="true"><span /></span>
    </label>
  );
}

export function StatCard({ label, value, detail, tone = "neutral" }: { label: string; value: string | number; detail?: string; tone?: Tone }) {
  return (
    <div className={`stat-card stat-card--${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <small>{detail}</small>}
    </div>
  );
}

export function EmptyState({ icon, title, description, action }: { icon?: ReactNode; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state__icon">{icon}</div>}
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function ProgressBar({ value, label }: { value: number; label?: string }) {
  const safeValue = Math.min(100, Math.max(0, value));
  return (
    <div className="progress-wrap">
      {label && <span>{label}</span>}
      <progress className="progress" max={100} value={safeValue} aria-label={label ?? "Postęp operacji"} />
    </div>
  );
}

export function ResultIcon({ state }: { state: "pass" | "warn" | "fail" | "pending" }) {
  if (state === "pass") return <CheckCircle2 className="result-icon result-icon--pass" size={20} aria-label="Poprawnie" />;
  if (state === "warn") return <AlertTriangle className="result-icon result-icon--warn" size={20} aria-label="Ostrzeżenie" />;
  if (state === "fail") return <XCircle className="result-icon result-icon--fail" size={20} aria-label="Błąd" />;
  return <LoaderCircle className="result-icon spin" size={20} aria-label="W toku" />;
}
