import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  CloudUpload,
  Download,
  FileArchive,
  GitMerge,
  History,
  Lock,
  PackageCheck,
  RefreshCcw,
  RotateCcw,
  Search,
  ServerCog,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import type { CapabilityStage, RestorePlan, ToolboxSession } from "../model";
import { formatDate, shortId, stageAllows } from "../model";
import { Button, Callout, Card, CardHeader, EmptyState, PageHeader, StatCard, StatusPill, Toggle } from "../components/Primitives";

interface RestorePageProps {
  query: string;
  onQueryChange: (query: string) => void;
  plan: RestorePlan | null;
  executionSession: ToolboxSession | null;
  apiMaxStage: CapabilityStage;
  writeEnabled: boolean;
  connected: boolean;
  busy: "plan" | "candidate" | "commit" | "push" | "download" | null;
  error: string | null;
  onCreatePlan: (mode: "ip" | "session") => void;
  onApplyCandidate: () => void;
  onCommit: (allowUnisolated: boolean, allowFull: boolean) => void;
  onPush: () => void;
  onDownloadConflicts: () => void;
  onOpenConnection: () => void;
}

export function RestorePage({ query, onQueryChange, plan, executionSession, apiMaxStage, writeEnabled, connected, busy, error, onCreatePlan, onApplyCandidate, onCommit, onPush, onDownloadConflicts, onOpenConnection }: RestorePageProps) {
  const [mode, setMode] = useState<"ip" | "session">(() => query.startsWith("cleanup-") ? "session" : "ip");
  const [allowUnisolated, setAllowUnisolated] = useState(false);
  const [allowFull, setAllowFull] = useState(false);
  useEffect(() => { if (query.startsWith("cleanup-")) setMode("session"); }, [query]);

  const state = executionSession?.state ?? plan?.state ?? "PLANNED";
  const safeEntities = useMemo(() => plan?.entities.filter((entity) => entity.outcome !== "conflict") ?? [], [plan]);
  const conflicts = useMemo(() => plan?.entities.filter((entity) => entity.outcome === "conflict") ?? [], [plan]);
  const candidateDone = ["RESTORED", "PARTIAL", "COMMITTING", "COMMITTED", "PUSHING", "PUSHED"].includes(state);
  const commitDone = ["COMMITTED", "PUSHING", "PUSHED"].includes(state);

  return (
    <div className="page-stack restore-page">
      <PageHeader
        eyebrow="Recovery / Emergency Restore"
        title="Odtwórz obiekt wraz z zależnościami"
        description="Merge trójstronny zachowuje zmiany powstałe po cleanupie i przywraca tylko bezpieczne komponenty sesji. Pełny config nigdy nie jest ładowany automatycznie."
        actions={plan && <StatusPill tone={conflicts.length ? "warning" : "success"}>{conflicts.length ? `${conflicts.length} konflikt` : "Gotowe do restore"}</StatusPill>}
      />

      {!connected && <Callout severity="warning" title="Restore wymaga bieżącego stanu Panorama" actions={<Button onClick={onOpenConnection}>Połącz</Button>}><p>Toolbox musi porównać backup sesji z aktualnym running i candidate.</p></Callout>}
      {error && <Callout severity="danger" title="Restore został zatrzymany"><p>{error}</p></Callout>}

      <Card className="restore-search-card">
        <div className="restore-search-card__copy"><div className="emergency-icon"><RotateCcw size={22} /></div><div><span className="eyebrow">Znajdź backup</span><h2>Co chcesz przywrócić?</h2><p>Wyszukaj konkretny adres albo otwórz całą sesję cleanup.</p></div></div>
        <div className="restore-search-card__form">
          <div className="segmented-control segmented-control--large"><button className={mode === "ip" ? "is-active" : ""} onClick={() => setMode("ip")}><Search size={15} /> Adres IP</button><button className={mode === "session" ? "is-active" : ""} onClick={() => setMode("session")}><History size={15} /> Session ID</button></div>
          <div className="restore-input"><input value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder={mode === "ip" ? "np. 10.42.8.17" : "cleanup-YYYYMMDD-HHMM-…"} spellCheck={false} /><Button variant="primary" loading={busy === "plan"} disabled={!connected || !query.trim()} onClick={() => onCreatePlan(mode)} icon={<GitMerge size={17} />}>Przelicz Restore</Button></div>
        </div>
      </Card>

      {!plan ? (
        <Card><EmptyState icon={<FileArchive size={28} />} title="Wybierz adres lub sesję" description="Toolbox odnajdzie backupy przechodnie, pobierze aktualny config i sklasyfikuje każdy komponent jako restore, already present albo conflict." /></Card>
      ) : (
        <>
          <div className="stats-grid stats-grid--4">
            <StatCard label="Sesje źródłowe" value={plan.sourceSessionIds?.length || 1} detail={`${shortId(plan.sourceSessionId)} · ${formatDate(plan.createdAt)}`} />
            <StatCard label="Bezpieczne komponenty" value={plan.safeComponentCount} detail={`${safeEntities.length} encji`} tone="success" />
            <StatCard label="Konflikty" value={plan.conflictComponentCount} detail={`${conflicts.length} encji`} tone={conflicts.length ? "danger" : "success"} />
            <StatCard label="Inverse patch" value={plan.operations.length} detail="operacji do candidate" tone="accent" />
          </div>

          <Card className="merge-card">
            <CardHeader title="Merge trójstronny" description="Decyzja jest podejmowana osobno dla każdej ścieżki zapisanej w sesji." action={<GitMerge size={21} />} />
            <div className="merge-flow">
              <div><span className="merge-node merge-node--base"><FileArchive size={18} /></span><p><strong>BASE</strong><span>stan przed cleanup</span><small>pre_running.xml</small></p></div>
              <ArrowDown className="merge-arrow" size={18} />
              <div><span className="merge-node merge-node--expected"><RefreshCcw size={18} /></span><p><strong>EXPECTED</strong><span>stan po cleanup</span><small>post_running fingerprint</small></p></div>
              <ArrowDown className="merge-arrow" size={18} />
              <div><span className="merge-node merge-node--current"><ServerCog size={18} /></span><p><strong>CURRENT</strong><span>aktualny stan Panorama</span><small>odczyt live</small></p></div>
              <div className="merge-decision"><GitMerge size={19} /><span><strong>Wynik</strong>Odtwórz, pomiń albo oznacz konflikt — bez nadpisania późniejszych zmian.</span></div>
            </div>
          </Card>

          {plan.warnings.map((warning) => <Callout severity="warning" title="Wykryto konflikt bieżącego stanu" key={warning} actions={<Button icon={<Download size={15} />} onClick={onDownloadConflicts} loading={busy === "download"}>Pakiet ręczny</Button>}><p>{warning}</p></Callout>)}

          <Card>
            <CardHeader title="Encje w closure zależności" description="Konflikt pomija cały zależny komponent; pozostałe komponenty mogą być przywrócone." action={<StatusPill tone="info">3-way verified</StatusPill>} />
            <div className="restore-components">
              {plan.entities.map((entity) => (
                <div key={entity.id} className={`restore-entity restore-entity--${entity.outcome}`}>
                  <span className="restore-entity__icon">{entity.outcome === "restore" ? <RotateCcw size={17} /> : entity.outcome === "already-present" ? <CheckCircle2 size={17} /> : <ShieldX size={17} />}</span>
                  <div><div><strong>{entity.name}</strong><StatusPill tone={entity.outcome === "restore" ? "accent" : entity.outcome === "already-present" ? "success" : "danger"}>{entity.outcome}</StatusPill></div><span>{entity.type} · {entity.scope}</span><small>{entity.detail}</small></div>
                  <code>{entity.componentId}</code>
                </div>
              ))}
            </div>
          </Card>

          <section className="restore-execution">
            <div className="execution-heading"><div><span className="eyebrow">Recovery execution</span><h2>Odtworzenie etapowe</h2><p>Inverse patch trafia najpierw do candidate. Commit i push pozostają osobnymi decyzjami.</p></div><StatusPill tone={writeEnabled ? "danger" : "neutral"}>{writeEnabled ? "API write aktywny" : "Read-only preview"}</StatusPill></div>
            {conflicts.length > 0 && <Callout severity="warning" title={`${plan.conflictComponentCount} komponent konfliktowy zostanie pominięty`}><p>Safe subset obejmuje wyłącznie komponenty niezależne. Dla konfliktów powstał osobny raport i pakiet ręczny.</p></Callout>}
            <div className="restore-stage-grid">
              <Card className={candidateDone ? "restore-stage restore-stage--done" : "restore-stage"}>
                <span>1</span><ServerCog size={21} /><h3>Restore Candidate</h3><p>Powtórny fingerprint, backup bieżącego stanu, inverse patch i validation.</p>
                {!stageAllows(apiMaxStage, "candidate") && <small className="stage-blocked"><Lock size={13} /> Zablokowane przez profil</small>}
                <Button variant="primary" loading={busy === "candidate"} disabled={!writeEnabled || !stageAllows(apiMaxStage, "candidate") || state !== "PLANNED"} onClick={onApplyCandidate}>Zastosuj safe subset</Button>
              </Card>
              <Card className={commitDone ? "restore-stage restore-stage--done" : "restore-stage"}>
                <span>2</span><PackageCheck size={21} /><h3>Commit Restore</h3><p>Partial commit operatora na Panorama. Ryzykowne rozszerzenia wymagają osobnej zgody.</p>
                <div className="compact-risk"><Toggle checked={allowUnisolated} onChange={(value) => { setAllowUnisolated(value); if (!value) setAllowFull(false); }} label="Unisolated" danger /><Toggle checked={allowFull} onChange={(value) => { setAllowFull(value); if (value) setAllowUnisolated(true); }} label="Full commit" danger /></div>
                {stageAllows(apiMaxStage, "commit") && !allowUnisolated && <small className="stage-blocked"><ShieldX size={13} /> Potwierdź zakres same-admin</small>}
                <Button variant={allowFull ? "danger" : "primary"} loading={busy === "commit"} disabled={!writeEnabled || !stageAllows(apiMaxStage, "commit") || (state !== "RESTORED" && state !== "PARTIAL") || !allowUnisolated} onClick={() => onCommit(allowUnisolated, allowFull)}>Commit Restore</Button>
              </Card>
              <Card className={state === "PUSHED" ? "restore-stage restore-stage--done" : "restore-stage"}>
                <span>3</span><CloudUpload size={21} /><h3>Push Restore</h3><p>Push wyłącznie do device groups wynikających z bezpiecznego closure.</p>
                <div className="restore-targets">{plan.affectedDeviceGroups.map((scope) => <StatusPill key={scope} tone="neutral">{scope}</StatusPill>)}</div>
                <Button variant="primary" loading={busy === "push"} disabled={!writeEnabled || !stageAllows(apiMaxStage, "push") || state !== "COMMITTED"} onClick={onPush}>Validate & Push Restore</Button>
              </Card>
            </div>
            {state === "RESTORED" ? <Callout severity="success" title="Restore zapisany do Candidate"><p>Safe subset został zastosowany i zwalidowany. Commit ani push nie zostały jeszcze uruchomione.</p></Callout> : null}
            {state === "PARTIAL" ? <Callout severity="warning" title="Częściowy Restore zapisany do Candidate"><p>Bezpieczne komponenty zostały zastosowane; konfliktowe komponenty pominięto. Po przejrzeniu pakietu ręcznego możesz commitować safe subset.</p></Callout> : null}
            {state === "PUSHED" ? <Callout severity="success" title="Restore zakończony"><p>Bezpieczne komponenty zostały odtworzone. Zmiany niezależne pozostały nietknięte, a konflikty są dostępne w pakiecie ręcznym.</p></Callout> : null}
          </section>

          <div className="restore-policy"><ShieldCheck size={20} /><div><strong>Pełny backup jest tylko źródłem prawdy</strong><p>Toolbox nie wywoła automatycznego load config, nawet podczas Emergency Restore. Każdy zapis jest ścieżkowym patchem z operacją odwrotną.</p></div><AlertTriangle size={19} /></div>
        </>
      )}
    </div>
  );
}
