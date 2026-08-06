import { Fragment, useEffect, useMemo, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CloudUpload,
  Download,
  FileArchive,
  GitCompareArrows,
  ListTree,
  PackageCheck,
  RotateCcw,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import type { AddressAnalysis, CandidateJob, CleanupPlan, EntityDependency, SessionState, ToolboxSession } from "../model";
import { formatDate, shortId } from "../model";
import { Button, Callout, Card, EmptyState, PageHeader, ProgressBar, StatusPill } from "../components/Primitives";

interface PlanPageProps {
  focus?: "plan" | "execute";
  plan: CleanupPlan | null;
  executionSession: ToolboxSession | null;
  candidateJob: CandidateJob | null;
  writeEnabled: boolean;
  busy: "candidate" | "commit" | "push" | "download" | null;
  singlePlanBusy: string | null;
  error: string | null;
  onOpenCleanup: () => void;
  onCreateSinglePlan: (target: AddressAnalysis) => void;
  onCreateSelectionPlan: (targets: AddressAnalysis[]) => void;
  onPlanDependencies: (dependencies: EntityDependency[], targets: AddressAnalysis[]) => void;
  onRestoreTarget: (target: AddressAnalysis) => void;
  onApplyCandidate: () => void;
  onCommit: () => void;
  onPush: () => void;
  onDownload: (artifact: "commands" | "report" | "manifest") => void;
}

const stateTone: Partial<Record<SessionState, "accent" | "success" | "danger" | "warning" | "info">> = {
  PLANNED: "info", WRITING_CANDIDATE: "warning", CANDIDATE_APPLIED: "warning", COMMITTING: "warning", COMMITTED: "accent", PUSHING: "warning", PUSHED: "success", FAILED: "danger", CONFLICT: "danger", PARTIAL: "warning", OUTCOME_UNKNOWN: "danger",
};

const decisionLabel = {
  process: "Gotowe do usunięcia",
  "skip-live": "Żywy — pominięty",
  "skip-error": "ICMP error — pominięty",
  "not-found": "Nie znaleziono",
  blocked: "Read-only / review",
};

function hitPresentation(value: { lastHit?: string; lastHitAgeDays?: number; hitCount?: number; lastHitStatus?: string }) {
  if (!value.lastHit || value.hitCount === 0 || value.lastHitStatus === "NEVER") return { className: "last-hit last-hit--green", label: "Brak hitów", detail: "brak Last Hit" };
  const age = value.lastHitAgeDays ?? Math.max(0, (Date.now() - new Date(value.lastHit).getTime()) / 86_400_000);
  if (age >= 183) return { className: "last-hit last-hit--green", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
  if (age >= 30) return { className: "last-hit last-hit--yellow", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
  if (age >= 14) return { className: "last-hit last-hit--orange", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
  return { className: "last-hit last-hit--red", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
}

export function PlanPage({ focus = "plan", plan, executionSession, candidateJob, writeEnabled, busy, singlePlanBusy, error, onOpenCleanup, onCreateSinglePlan, onCreateSelectionPlan, onPlanDependencies, onRestoreTarget, onApplyCandidate, onCommit, onPush, onDownload }: PlanPageProps) {
  const [expandedTargets, setExpandedTargets] = useState<Set<string>>(new Set());
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
  const [selectedDependencies, setSelectedDependencies] = useState<Map<string, EntityDependency>>(new Map());
  const [confirmAction, setConfirmAction] = useState<"commit" | "push" | null>(null);
  useEffect(() => { setSelectedTargets(new Set()); setSelectedDependencies(new Map()); }, [plan?.sessionId]);
  const state = executionSession?.state ?? plan?.state ?? "PLANNED";

  const stages = useMemo(() => [
    { label: "Plan", icon: ListTree },
    { label: "Candidate", icon: ServerCog },
    { label: "Commit", icon: PackageCheck },
    { label: "Push", icon: CloudUpload },
  ], []);
  const stageIndex = state === "WRITING_CANDIDATE" || state === "CANDIDATE_APPLIED" || state === "PARTIAL" ? 1 : state === "COMMITTING" || state === "COMMITTED" ? 2 : state === "PUSHING" || state === "PUSHED" ? 3 : 0;

  if (!plan) return <div className={`page-stack plan-page plan-page--${focus}`}><PageHeader eyebrow={`Workflow / ${focus === "execute" ? "Wykonaj" : "Plan"}`} title={focus === "execute" ? "Brak planu do wykonania" : "Plan zmian"} description="Najpierw wyszukaj cele i przygotuj plan. Żaden zapis API nie uruchamia się automatycznie." /><Card><EmptyState icon={<ListTree size={27} />} title="Nie ma jeszcze planu" description="Lista pokaże szczegóły polityk, zależności i backup każdej encji." action={<Button variant="primary" onClick={onOpenCleanup}>Utwórz plan</Button>} /></Card></div>;

  const selectedTargetRows = plan.addresses.filter((target) => selectedTargets.has(target.ip));
  const canApplyCandidate = state === "PLANNED";
  const canCommit = state === "CANDIDATE_APPLIED" || state === "PARTIAL";
  const canPush = state === "COMMITTED";
  const canRestore = ["CANDIDATE_APPLIED", "PARTIAL", "COMMITTED", "PUSHED"].includes(state);

  const toggleTarget = (target: AddressAnalysis) => setSelectedTargets((current) => {
    const next = new Set(current);
    if (next.has(target.ip)) next.delete(target.ip); else next.add(target.ip);
    return next;
  });
  const toggleDependency = (dependency: EntityDependency, target: AddressAnalysis) => setSelectedDependencies((current) => {
    const next = new Map(current);
    if (next.has(dependency.id)) next.delete(dependency.id); else {
      next.set(dependency.id, dependency);
      setSelectedTargets((targets) => new Set(targets).add(target.ip));
    }
    return next;
  });

  return (
    <div className={`page-stack plan-page plan-page--${focus}`}>
      <PageHeader eyebrow={`Session / ${shortId(plan.sessionId)}`} title={focus === "execute" ? "Wykonaj operacje XML API" : "Cele i zależności"} description={focus === "execute" ? "Backup → locki → live fingerprint → osobne operacje XPath → walidacja Candidate." : "Rozwiń dowolny wiersz. Szczegóły analizy technicznej są zebrane w jednym panelu na dole."} actions={<><StatusPill tone={stateTone[state] ?? "neutral"}>{state.replaceAll("_", " ")}</StatusPill><Button icon={<Download size={16} />} loading={busy === "download"} onClick={() => onDownload("report")}>Raport</Button></>} />
      {error && <Callout severity="danger" title="Operacja została zatrzymana"><p>{error}</p></Callout>}

      <Card className="stage-rail-card"><div className="stage-rail">{stages.map((stage, index) => { const Icon = stage.icon; const done = index < stageIndex || state === "PUSHED"; const active = index === stageIndex && state !== "PUSHED"; return <div key={stage.label} className={`${done ? "is-done" : ""} ${active ? "is-active" : ""}`}><span className="stage-rail__icon">{done ? <Check size={17} /> : <Icon size={17} />}</span><div><small>Etap {index + 1}</small><strong>{stage.label}</strong></div>{index < stages.length - 1 && <i />}</div>; })}</div></Card>

      <Card className="plan-entity-card">
        <div className="plan-list-toolbar">
          <div><strong>{plan.addresses.length} celów</strong><span>{plan.processCount} wykonywalnych · {plan.operations.length} operacji XPath · {plan.addresses.reduce((sum, target) => sum + (target.backupFiles?.length ?? 0), 0)} backupów encji</span></div>
          <div>{selectedTargets.size > 0 && <><span className="selection-counter">{selectedTargets.size} zazn.</span><Button loading={singlePlanBusy === "selection"} disabled={Boolean(singlePlanBusy)} onClick={() => onCreateSelectionPlan(selectedTargetRows)}>Utwórz plan tylko z zaznaczonych</Button></>}</div>
        </div>
        <div className="responsive-table plan-table policy-plan-table"><table>
          <thead><tr><th><span className="visually-hidden">Zaznacz</span></th><th>Cel / lokalizacja</th><th>Last Hit</th><th>Zależności</th><th>Backup</th><th>Decyzja</th><th>Akcja</th><th /></tr></thead>
          <tbody>{plan.addresses.map((target, index) => {
            const expanded = expandedTargets.has(target.ip);
            const hit = hitPresentation(target);
            const locations = (target.entities ?? []).map((entity) => `${entity.scope} · ${entity.rulebase ?? entity.type}`).join(" | ");
            return <Fragment key={target.ip}>
              <tr className={target.decision === "blocked" ? "row-warning" : ""}>
                <td><input type="checkbox" checked={selectedTargets.has(target.ip)} disabled={target.decision !== "process"} onChange={() => toggleTarget(target)} aria-label={`Zaznacz ${target.label ?? target.ip}`} /></td>
                <td><div className="entity-cell"><span className="row-index">{index + 1}</span><span><strong>{target.label ?? target.ip}</strong><small>{target.targetType ?? "ip"} · {locations || "brak dopasowania"}</small></span></div></td>
                <td><span className={hit.className}><b>{hit.label}</b><small>{hit.detail}</small></span></td>
                <td><span className="reference-count" title="Rzeczywiste zależności encji, nie CLI/API">{target.references.length}</span></td>
                <td><span className="backup-count"><FileArchive size={14} />{target.backupFiles?.length ?? 0}</span></td>
                <td><StatusPill tone={target.decision === "process" ? "accent" : target.decision === "skip-live" ? "success" : target.decision === "blocked" ? "warning" : target.decision === "skip-error" ? "danger" : "neutral"}>{decisionLabel[target.decision]}</StatusPill></td>
                <td><div className="row-actions"><Button variant="ghost" loading={singlePlanBusy === target.ip} disabled={target.decision !== "process" || !target.componentId || Boolean(singlePlanBusy)} onClick={() => onCreateSinglePlan(target)}>Tylko ten</Button>{canRestore && (target.backupFiles?.length ?? 0) > 0 && <Button variant="ghost" onClick={() => onRestoreTarget(target)} icon={<RotateCcw size={14} />}>Restore</Button>}</div></td>
                <td><button className="table-expand" disabled={!(target.entities?.length ?? 0) && !target.references.length && !(target.backupFiles?.length ?? 0)} onClick={() => setExpandedTargets((current) => { const next = new Set(current); if (next.has(target.ip)) next.delete(target.ip); else next.add(target.ip); return next; })} aria-label={`Rozwiń ${target.label ?? target.ip}`}>{expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</button></td>
              </tr>
              {expanded && <tr className="expanded-row"><td colSpan={8}><div className="target-inspector">
                {target.targetType === "policy" && <div className="policy-delete-note"><ShieldCheck size={16} /><span><strong>Domyślnie usuwana jest tylko wskazana polityka.</strong> Obiekty source/destination pozostają. Zaznacz je niżej, jeśli mają zostać jawnymi celami nowego planu.</span></div>}
                {(target.entities ?? []).map((entity) => <section key={entity.id} className="entity-inspection">
                  <header><div><span className={`entity-type-dot entity-type-dot--${entity.type}`} /><span><strong>{entity.name}</strong><small>{entity.scope} · {entity.rulebase ?? entity.type} · {entity.policyType ?? ""}</small></span></div>{entity.readOnly ? <StatusPill tone="warning">Read-only</StatusPill> : <StatusPill tone="success">API XPath</StatusPill>}</header>
                  {entity.blockedReason && <Callout severity="warning" title="Nie zostanie wykonane automatycznie"><p>{entity.blockedReason}</p></Callout>}
                  <dl className="entity-field-grid">{entity.fields.map((field, fieldIndex) => <div key={`${field.k}-${fieldIndex}`}><dt>{field.k}</dt><dd>{field.v}</dd></div>)}</dl>
                  {entity.type === "policy" && <div className={`entity-last-hit ${hitPresentation(entity).className}`}><span><strong>Hit count</strong><b>{entity.hitCount ?? 0}</b></span><span><strong>Last Hit</strong><b>{entity.lastHit ? formatDate(entity.lastHit) : "brak"}</b></span><small>{entity.lastHitDetail}</small></div>}
                  <div className="dependency-tree"><h4><ListTree size={16} /> Zależności ({entity.dependencies.length})</h4>{entity.dependencies.length ? entity.dependencies.map((dependency) => <label key={dependency.id} className={dependency.readOnly ? "is-read-only" : ""}><input type="checkbox" checked={selectedDependencies.has(dependency.id)} disabled={dependency.readOnly || !["address", "address-group", "policy"].includes(dependency.type)} onChange={() => toggleDependency(dependency, target)} /><span className={`entity-type-dot entity-type-dot--${dependency.type}`} /><span><strong>{dependency.name}</strong><small>{dependency.type} · {dependency.relation ?? dependency.field} · {dependency.scope}{dependency.rulebase ? ` · ${dependency.rulebase}` : ""}</small></span>{dependency.type === "policy" && <span className={hitPresentation(dependency).className}><b>{dependency.hitCount ?? 0} hit</b><small>{dependency.lastHit ? formatDate(dependency.lastHit) : "brak Last Hit"}</small></span>}{dependency.readOnly && <StatusPill tone="warning">Read-only</StatusPill>}</label>) : <p className="muted-value">Brak zależności dla tej encji.</p>}</div>
                  <code className="inspector-xpath">{entity.path}</code>
                </section>)}
                <div className="entity-backups"><h4><FileArchive size={16} /> Backup per encja / operacja</h4>{target.backupFiles?.length ? target.backupFiles.map((backup) => <div key={backup.mutationId}><span><strong>{backup.entityName}</strong><small>{backup.entityType} · {backup.mutationId}</small></span><code>{backup.file}</code></div>) : <span className="muted-value">Brak mutacji — nie utworzono pliku backupu.</span>}</div>
              </div></td></tr>}
            </Fragment>;
          })}</tbody>
        </table></div>
        {selectedDependencies.size > 0 && <div className="dependency-selection-bar"><span><strong>{selectedDependencies.size}</strong> zależności + {selectedTargetRows.length} wskazanych celów</span><Button variant="primary" onClick={() => onPlanDependencies([...selectedDependencies.values()], selectedTargetRows)} icon={<ArrowRight size={16} />}>Nowy batch z zależnościami</Button></div>}
      </Card>

      <section className="execution-section execute-only">
        <div className="execution-heading"><div><span className="eyebrow">Path-by-path XML API</span><h2>Wykonanie kontrolowane</h2><p>Każda operacja ma własny XPath, fingerprint, backup i wynik. Pełny config nie jest wgrywany na urządzenie.</p></div><StatusPill tone={writeEnabled ? "success" : "info"}>{writeEnabled ? "WRITE aktywny" : "READ ONLY"}</StatusPill></div>
        {!writeEnabled && <Callout severity="info" title="Przełącz górny suwak na zielony WRITE"><p>To jedyna bramka zapisu w GUI. Po potwierdzeniu Candidate, commit i push będą dostępne jako trzy osobne kroki.</p></Callout>}
        <div className="execution-grid">
          <Card className={["CANDIDATE_APPLIED", "PARTIAL", "COMMITTED", "PUSHED"].includes(state) ? "stage-card stage-card--done" : "stage-card"}><span className="stage-number">01</span><CheckCircle2 className="done-icon" /><h3>Candidate po XPath</h3><p>Backup encji → locki → live recheck → jedna operacja API po drugiej → validate.</p><Button variant="primary" loading={busy === "candidate"} disabled={!writeEnabled || !canApplyCandidate} onClick={onApplyCandidate}>Zapisz Candidate przez API</Button></Card>
          <Card className={["COMMITTED", "PUSHED"].includes(state) ? "stage-card stage-card--done" : "stage-card"}><span className="stage-number">02</span><PackageCheck /><h3>Commit Panorama</h3><p>Osobny partial commit administratora. Przed startem zobaczysz ostrzeżenie z zakresem.</p><Button variant="primary" loading={busy === "commit"} disabled={!writeEnabled || !canCommit} onClick={() => setConfirmAction("commit")}>Commit</Button></Card>
          <Card className={state === "PUSHED" ? "stage-card stage-card--done" : "stage-card"}><span className="stage-number">03</span><CloudUpload /><h3>Push do urządzeń</h3><p>Osobny job tylko do device groups wynikających z planu.</p><div className="push-targets">{plan.affectedDeviceGroups.map((group) => <StatusPill key={group}>{group}</StatusPill>)}</div><Button variant="primary" loading={busy === "push"} disabled={!writeEnabled || !canPush} onClick={() => setConfirmAction("push")}>Validate & Push</Button></Card>
        </div>
        {candidateJob && <Card className="candidate-progress-card" aria-live="polite"><div className="candidate-progress-head"><div><ServerCog className={candidateJob.state === "running" ? "spin" : ""} size={19} /><span><strong>{candidateJob.message}</strong><small>{candidateJob.current?.entityKey ?? "Bezpieczne przygotowanie sesji"}</small></span></div><b>{candidateJob.progress}%</b></div><ProgressBar value={candidateJob.progress} label={`${candidateJob.progress}%`} /><div className="candidate-operation-log">{candidateJob.items.slice(-6).map((item, index) => <div key={`${item.mutationId}-${index}`}><CheckCircle2 size={14} /><span><strong>{item.entityKey}</strong><small>{item.action} · operacja {item.completedOperations}/{item.totalOperations}</small></span></div>)}</div></Card>}
        {executionSession?.jobs.length ? <Card className="jobs-card">{executionSession.jobs.map((job) => <div className="job-row" key={job.id}><div><StatusPill tone={job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning"}>{job.state}</StatusPill><div><strong>{job.kind.toUpperCase()} · {job.id}</strong><span>{job.message}</span></div></div><ProgressBar value={job.progress} label={`${job.progress}%`} /></div>)}</Card> : null}
      </section>

      <details className="analysis-details-drawer">
        <summary><span><GitCompareArrows size={18} /><span><strong>Szczegóły analizy, diff, ostrzeżenia i operacje API</strong><small>Jedno rozwijane okno · nie zasłania listy polityk</small></span></span><ChevronDown size={18} /></summary>
        <div className="analysis-details-content">
          <div className="analysis-summary-grid"><div><strong>Running ↔ Candidate</strong><span>{plan.diff.summary}</span><small>Natywne: {plan.diff.nativeEntries} · semantyczne: {plan.diff.semanticEntries}</small></div><div><strong>Device groups</strong><span>{plan.affectedDeviceGroups.join(", ") || "shared"}</span><small>Zakres push jest wyliczony z dotkniętych XPath.</small></div><div><strong>Bezpieczeństwo</strong><span>SHA256 · lock · per-XPath fingerprint</span><small>Candidate jest odczytywany live przed zapisem.</small></div></div>
          {plan.warnings.map((warning) => <Callout severity={warning.includes("Application Override") ? "warning" : "info"} title={warning.includes("Application Override") ? "Application Override — read-only" : "Informacja z analizy"} key={warning}><p>{warning}</p></Callout>)}
          <div className="analysis-downloads"><Button icon={<Download size={15} />} onClick={() => onDownload("commands")}>Podgląd CLI</Button><Button icon={<Download size={15} />} onClick={() => onDownload("report")}>Raport</Button><Button icon={<Download size={15} />} onClick={() => onDownload("manifest")}>Manifest + backupy</Button></div>
          <div className="responsive-table operations-table"><table><thead><tr><th>#</th><th>API</th><th>Encja</th><th>Zakres</th><th>XPath / rollback</th></tr></thead><tbody>{plan.operations.map((operation) => <tr key={operation.id}><td>{operation.order}</td><td><StatusPill tone={operation.action === "delete" ? "danger" : "warning"}>{operation.action.toUpperCase()}</StatusPill></td><td><strong>{operation.entityName}</strong><small>{operation.entityType}</small></td><td>{operation.scope}</td><td><code>{operation.xpath}</code><small><ShieldCheck size={12} /> {operation.inverseSummary}</small></td></tr>)}</tbody></table></div>
        </div>
      </details>

      <div className="safety-footer"><AlertOctagon size={18} /><span><strong>Restore jest ścieżkowy.</strong> Kliknij Restore przy konkretnym celu albo odtwórz całą sesję; closure zależności jest liczone z backupów.</span><ArrowRight size={18} /></div>

      {confirmAction && <div className="write-confirm-backdrop"><div className={`write-confirm ${confirmAction === "push" ? "write-confirm--critical" : ""}`} role="dialog" aria-modal="true"><div><AlertTriangle size={22} /><strong>{confirmAction === "commit" ? "Potwierdź commit do Panorama" : "UWAGA: potwierdź push do urządzeń"}</strong></div><p>{confirmAction === "commit" ? "Candidate zostanie utrwalony partial commitem bieżącego administratora. To nadal nie wykonuje push do firewalli." : `Zmiany zostaną wysłane do: ${plan.affectedDeviceGroups.join(", ") || "zakresu shared"}. Zweryfikuj zakres i stan urządzeń przed kontynuacją.`}</p><div><Button onClick={() => setConfirmAction(null)}>Anuluj</Button><Button variant={confirmAction === "push" ? "danger" : "primary"} onClick={() => { const action = confirmAction; setConfirmAction(null); if (action === "commit") onCommit(); else onPush(); }}>{confirmAction === "commit" ? "Tak, uruchom commit" : "Tak, wykonaj PUSH"}</Button></div></div></div>}
    </div>
  );
}
