import { Fragment, useEffect, useMemo, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Ban,
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
  Search,
  ServerCog,
  ShieldCheck,
  Undo2,
} from "lucide-react";
import type { AddressAnalysis, CleanupPlan, EntityDependency, ExecutionJob, SessionState, ToolboxSession } from "../model";
import { formatDate, shortId } from "../model";
import { ExecutionProgress } from "../components/ExecutionProgress";
import { Button, Callout, Card, EmptyState, PageHeader, ProgressBar, StatusPill } from "../components/Primitives";

interface PlanPageProps {
  focus?: "plan" | "execute";
  plan: CleanupPlan | null;
  executionSession: ToolboxSession | null;
  executionJob: ExecutionJob | null;
  writeEnabled: boolean;
  busy: "candidate" | "commit" | "push" | "download" | null;
  singlePlanBusy: string | null;
  error: string | null;
  onOpenCleanup: () => void;
  onCreateSinglePlan: (target: AddressAnalysis) => void;
  onCreateSelectionPlan: (targets: AddressAnalysis[]) => void;
  onExcludeTargets: (targets: AddressAnalysis[]) => void;
  onExcludeComponents: (componentIds: string[]) => void;
  onUndoLastExclusion: () => void;
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
  excluded: "Wykluczony z wykonania",
};

function hitPresentation(value: { lastHit?: string; lastHitAgeDays?: number; hitCount?: number; lastHitStatus?: string }) {
  if (!value.lastHit || value.hitCount === 0 || value.lastHitStatus === "NEVER") return { className: "last-hit last-hit--green", label: "Brak hitów", detail: "brak Last Hit" };
  const age = value.lastHitAgeDays ?? Math.max(0, (Date.now() - new Date(value.lastHit).getTime()) / 86_400_000);
  if (age >= 183) return { className: "last-hit last-hit--green", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
  if (age >= 30) return { className: "last-hit last-hit--yellow", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
  if (age >= 14) return { className: "last-hit last-hit--orange", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
  return { className: "last-hit last-hit--red", label: `${Math.floor(age)} dni`, detail: formatDate(value.lastHit) };
}

export function PlanPage({ focus = "plan", plan, executionSession, executionJob, writeEnabled, busy, singlePlanBusy, error, onOpenCleanup, onCreateSinglePlan, onCreateSelectionPlan, onExcludeTargets, onExcludeComponents, onUndoLastExclusion, onPlanDependencies, onRestoreTarget, onApplyCandidate, onCommit, onPush, onDownload }: PlanPageProps) {
  const [expandedTargets, setExpandedTargets] = useState<Set<string>>(new Set());
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
  const [selectedDependencies, setSelectedDependencies] = useState<Map<string, EntityDependency>>(new Map());
  const [confirmAction, setConfirmAction] = useState<"candidate" | "commit" | "push" | null>(null);
  const [objectQuery, setObjectQuery] = useState("");
  useEffect(() => { setSelectedTargets(new Set()); setSelectedDependencies(new Map()); }, [plan?.sessionId]);
  useEffect(() => { setObjectQuery(""); }, [plan?.sessionId]);
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
  const sortedAddresses = useMemo(() => [...plan.addresses].sort((left, right) => {
    const age = (target: AddressAnalysis) => {
      if (!target.lastHit || target.hitCount === 0 || target.lastHitStatus === "NEVER") return Number.POSITIVE_INFINITY;
      return target.lastHitAgeDays ?? Math.max(0, (Date.now() - new Date(target.lastHit).getTime()) / 86_400_000);
    };
    const byAge = age(left) - age(right);
    return byAge !== 0 ? byAge : (left.label ?? left.ip).localeCompare(right.label ?? right.ip, "pl");
  }), [plan.addresses]);
  const normalizedQuery = objectQuery.trim().toLocaleLowerCase("pl");
  const filteredAddresses = useMemo(() => {
    if (!normalizedQuery) return sortedAddresses;
    return sortedAddresses.filter((target) => {
      const values = [
        target.ip,
        target.label,
        target.targetType,
        ...(target.objectNames ?? []),
        ...(target.entities ?? []).flatMap((entity) => [entity.name, entity.type, entity.scope, entity.rulebase, entity.policyType, entity.path]),
        ...(target.references ?? []).flatMap((reference) => [reference.name, reference.type, reference.scope, reference.deviceGroup, reference.rulebase, reference.policyType, reference.path]),
      ];
      return values.filter(Boolean).some((value) => String(value).toLocaleLowerCase("pl").includes(normalizedQuery));
    });
  }, [normalizedQuery, sortedAddresses]);
  const filteredOperations = useMemo(() => {
    if (!normalizedQuery) return plan.operations;
    return plan.operations.filter((operation) => [operation.entityName, operation.entityType, operation.scope, operation.xpath, operation.summary, operation.inverseSummary].some((value) => value.toLocaleLowerCase("pl").includes(normalizedQuery)));
  }, [normalizedQuery, plan.operations]);
  const canApplyCandidate = state === "PLANNED" && plan.operations.length > 0;
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
      <PageHeader eyebrow={`Session / ${shortId(plan.sessionId)}`} title={focus === "execute" ? "Wykonaj operacje XML API" : plan.kind === "future-create" ? "Plan tworzenia polityk i obiektów" : "Cele i zależności"} description={focus === "execute" ? "Backup → locki → live fingerprint → osobne operacje XPath → walidacja Candidate." : plan.kind === "future-create" ? "Zweryfikuj nazwy, DG, strefy i XPath. Candidate pozostaje osobnym, świadomym krokiem." : "Rozwiń dowolny wiersz. Szczegóły analizy technicznej są zebrane w jednym panelu na dole."} actions={<><StatusPill tone={stateTone[state] ?? "neutral"}>{state.replaceAll("_", " ")}</StatusPill><Button icon={<Download size={16} />} loading={busy === "download"} onClick={() => onDownload("report")}>Raport</Button></>} />
      {error && <Callout severity="danger" title="Operacja została zatrzymana"><p>{error}</p></Callout>}
      {plan.addresses.some((target) => target.defaultPolicyProtected) && !plan.defaultPolicyOverride && <Callout severity="warning" title="DEFAULT chroniona"><p>Pozycje dotykające polityki DEFAULT zostały automatycznie wykluczone razem z zależnościami. Override włącza się wyłącznie przed nową analizą i wymaga świadomej akceptacji.</p></Callout>}
      {plan.defaultPolicyOverride && plan.warnings.some((warning) => warning.includes("DEFAULT")) && <Callout severity="danger" title="DEFAULT override w tym planie"><p>Ten plan może naruszyć politykę DEFAULT. Przed Candidate sprawdź dokładny XPath i zależności.</p></Callout>}

      <Card className="stage-rail-card"><div className="stage-rail">{stages.map((stage, index) => { const Icon = stage.icon; const done = index < stageIndex || state === "PUSHED"; const active = index === stageIndex && state !== "PUSHED"; return <div key={stage.label} className={`${done ? "is-done" : ""} ${active ? "is-active" : ""}`}><span className="stage-rail__icon">{done ? <Check size={17} /> : <Icon size={17} />}</span><div><small>Etap {index + 1}</small><strong>{stage.label}</strong></div>{index < stages.length - 1 && <i />}</div>; })}</div></Card>

      <Card className="plan-entity-card">
        <div className="plan-list-toolbar">
          <div><strong>{plan.addresses.length} celów</strong><span>{plan.processCount} wykonywalnych · {plan.excludedCount ?? 0} wykluczonych · {plan.operations.length} operacji XPath · {plan.addresses.reduce((sum, target) => sum + (target.backupFiles?.length ?? 0), 0)} backupów encji</span></div>
          <div className="table-search plan-search"><Search size={16} /><input value={objectQuery} onChange={(event) => setObjectQuery(event.target.value)} placeholder="Szukaj obiektu / polityki / IP / DG / XPath…" aria-label="Szukaj w planie" /></div>
          <div>{selectedTargets.size > 0 && <><span className="selection-counter">{selectedTargets.size} zazn.</span><Button variant="danger" icon={<Ban size={15} />} loading={singlePlanBusy === "exclude-selection" || (selectedTargetRows.length === 1 && singlePlanBusy === `exclude:${selectedTargetRows[0]?.ip}`)} disabled={Boolean(singlePlanBusy)} onClick={() => onExcludeTargets(selectedTargetRows)}>Wyklucz zaznaczone</Button><Button loading={singlePlanBusy === "selection"} disabled={Boolean(singlePlanBusy)} onClick={() => onCreateSelectionPlan(selectedTargetRows)}>Plan tylko z zaznaczonych</Button></>}</div>
        </div>
        {objectQuery.trim() && <div className="plan-search-result"><Search size={15} /><span>Dopasowanie: <strong>{filteredAddresses.length}</strong> celów, <strong>{filteredOperations.length}</strong> operacji. Ten sam filtr jest widoczny w przeglądzie przed commitem.</span></div>}
        <div className="recent-exclusion-toolbar" aria-label="Szybkie wykluczenia Last Hit"><span><strong>Last Hit:</strong> wyklucz świeże cele</span>{[14, 30, 90].map((days) => { const candidates = sortedAddresses.filter((target) => { if (target.decision !== "process" || !target.lastHit || target.hitCount === 0 || target.lastHitStatus === "NEVER") return false; const age = target.lastHitAgeDays ?? Math.max(0, (Date.now() - new Date(target.lastHit).getTime()) / 86_400_000); return age < days; }); return <Button key={days} variant="ghost" disabled={!candidates.length || Boolean(singlePlanBusy)} loading={singlePlanBusy === "exclude-selection"} onClick={() => onExcludeTargets(candidates)}>{days === 14 ? "<14 dni" : days === 30 ? "<1 miesiąc" : "<3 miesiące"} ({candidates.length})</Button>; })}</div>
        {(plan.excludedCount ?? 0) > 0 && <div className="exclusion-summary"><div><Ban size={18} /><span><strong>{plan.excludedCount} {plan.excludedCount === 1 ? "cel" : "celów"} poza wykonaniem</strong><small>{plan.excludedTargets?.length ?? 0} wskazano bezpośrednio · {plan.excludedComponentIds?.length ?? 0} komponentów wyłączono. Pozostałe cele wynikają ze wspólnych atomowych zależności. Nie trafią do Candidate, backupów ani operacji XPath tej sesji.</small></span></div>{plan.parentSessionId && <Button icon={<Undo2 size={15} />} loading={singlePlanBusy === "undo-exclusion"} disabled={Boolean(singlePlanBusy)} onClick={onUndoLastExclusion}>Cofnij ostatnie wykluczenie</Button>}</div>}
        <div className="responsive-table plan-table policy-plan-table"><table>
          <thead><tr><th><span className="visually-hidden">Zaznacz</span></th><th>Cel / lokalizacja</th><th>Last Hit</th><th>Zależności</th><th>Backup</th><th>Decyzja</th><th>Akcja</th><th /></tr></thead>
          <tbody>{filteredAddresses.map((target, index) => {
            const expanded = expandedTargets.has(target.ip);
            const hit = hitPresentation(target);
            const locations = (target.entities ?? []).map((entity) => `${entity.scope} · ${entity.rulebase ?? entity.type}`).join(" | ");
            const executionComponents = [...new Set(target.componentIds ?? (target.componentId ? [target.componentId] : []))]
              .map((componentId) => ({ componentId, operations: plan.operations.filter((operation) => operation.componentId === componentId) }))
              .filter((component) => component.operations.length > 0);
            return <Fragment key={target.ip}>
              <tr className={`${target.decision === "blocked" ? "row-warning" : ""} ${target.decision === "excluded" ? "row-excluded" : ""}`}>
                <td><input type="checkbox" checked={selectedTargets.has(target.ip)} disabled={target.decision !== "process"} onChange={() => toggleTarget(target)} aria-label={`Zaznacz ${target.label ?? target.ip}`} /></td>
                <td><div className="entity-cell"><span className="row-index">{index + 1}</span><span><strong>{target.label ?? target.ip}</strong><small>{target.targetType ?? "ip"} · {locations || "brak dopasowania"}</small></span></div></td>
                <td><span className={hit.className}><b>{hit.label}</b><small>{hit.detail}</small></span></td>
                <td><span className="reference-count" title="Rzeczywiste zależności encji, nie CLI/API">{target.references.length}</span></td>
                <td><span className="backup-count"><FileArchive size={14} />{target.backupFiles?.length ?? 0}</span></td>
                <td><StatusPill tone={target.decision === "process" ? "accent" : target.decision === "skip-live" ? "success" : target.decision === "blocked" ? "warning" : target.decision === "skip-error" ? "danger" : "neutral"}>{decisionLabel[target.decision]}</StatusPill>{target.exclusionReason && <small className="exclusion-reason">{target.exclusionReason}</small>}</td>
                <td><div className="row-actions"><Button variant="ghost" icon={<Ban size={14} />} loading={singlePlanBusy === `exclude:${target.ip}`} disabled={target.decision !== "process" || Boolean(singlePlanBusy)} onClick={() => onExcludeTargets([target])}>Wyklucz</Button><Button variant="ghost" loading={singlePlanBusy === target.ip} disabled={target.decision !== "process" || !target.componentId || Boolean(singlePlanBusy)} onClick={() => onCreateSinglePlan(target)}>Tylko ten</Button>{canRestore && (target.backupFiles?.length ?? 0) > 0 && <Button variant="ghost" onClick={() => onRestoreTarget(target)} icon={<RotateCcw size={14} />}>Restore</Button>}</div></td>
                <td><button className="table-expand" disabled={!(target.entities?.length ?? 0) && !target.references.length && !(target.backupFiles?.length ?? 0)} onClick={() => setExpandedTargets((current) => { const next = new Set(current); if (next.has(target.ip)) next.delete(target.ip); else next.add(target.ip); return next; })} aria-label={`Rozwiń ${target.label ?? target.ip}`}>{expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</button></td>
              </tr>
              {expanded && <tr className="expanded-row"><td colSpan={8}><div className="target-inspector">
                {target.targetType === "policy" && plan.kind !== "future-create" && <div className="policy-delete-note"><ShieldCheck size={16} /><span><strong>Domyślnie usuwana jest tylko wskazana polityka.</strong> Obiekty source/destination pozostają. Zaznacz je niżej, jeśli mają zostać jawnymi celami nowego planu.</span></div>}
                {(target.entities ?? []).map((entity) => <section key={entity.id} className="entity-inspection">
                  <header><div><span className={`entity-type-dot entity-type-dot--${entity.type}`} /><span><strong>{entity.name}</strong><small>{entity.scope} · {entity.rulebase ?? entity.type} · {entity.policyType ?? ""}</small></span></div>{entity.readOnly ? <StatusPill tone="warning">Read-only</StatusPill> : <StatusPill tone="success">API XPath</StatusPill>}</header>
                  {entity.blockedReason && <Callout severity="warning" title="Nie zostanie wykonane automatycznie"><p>{entity.blockedReason}</p></Callout>}
                  <dl className="entity-field-grid">{entity.fields.map((field, fieldIndex) => <div key={`${field.k}-${fieldIndex}`}><dt>{field.k}</dt><dd>{field.v}</dd></div>)}</dl>
                  {entity.type === "policy" && <div className={`entity-last-hit ${hitPresentation(entity).className}`}><span><strong>Hit count</strong><b>{entity.hitCount ?? 0}</b></span><span><strong>Last Hit</strong><b>{entity.lastHit ? formatDate(entity.lastHit) : "brak"}</b></span><small>{entity.lastHitDetail}</small></div>}
                  <div className="dependency-tree"><h4><ListTree size={16} /> Zależności ({entity.dependencies.length})</h4>{entity.dependencies.length ? entity.dependencies.map((dependency) => <label key={dependency.id} className={dependency.readOnly ? "is-read-only" : ""}><input type="checkbox" checked={selectedDependencies.has(dependency.id)} disabled={dependency.readOnly || !["address", "address-group", "policy"].includes(dependency.type)} onChange={() => toggleDependency(dependency, target)} /><span className={`entity-type-dot entity-type-dot--${dependency.type}`} /><span><strong>{dependency.name}</strong><small>{dependency.type} · {dependency.relation ?? dependency.field} · {dependency.scope}{dependency.rulebase ? ` · ${dependency.rulebase}` : ""}</small></span>{dependency.type === "policy" && <span className={hitPresentation(dependency).className}><b>{dependency.hitCount ?? 0} hit</b><small>{dependency.lastHit ? formatDate(dependency.lastHit) : "brak Last Hit"}</small></span>}{dependency.readOnly && <StatusPill tone="warning">Read-only</StatusPill>}</label>) : <p className="muted-value">Brak zależności dla tej encji.</p>}</div>
                  <code className="inspector-xpath">{entity.path}</code>
                </section>)}
                {executionComponents.length > 0 && <div className="execution-components"><h4><ShieldCheck size={16} /> Atomowe komponenty wykonawcze</h4>{executionComponents.map((component) => <section key={component.componentId}><div><strong>{component.operations.length} {component.operations.length === 1 ? "operacja" : "operacji"}</strong><small>{component.componentId}</small></div><ul>{component.operations.map((operation) => <li key={operation.id}><StatusPill tone={operation.action === "delete" ? "danger" : "warning"}>{operation.action.toUpperCase()}</StatusPill><span><strong>{operation.entityName}</strong><small>{operation.entityType} · {operation.scope}</small></span></li>)}</ul><Button variant="danger" icon={<Ban size={14} />} loading={singlePlanBusy === `exclude-component:${component.componentId}`} disabled={Boolean(singlePlanBusy)} onClick={() => onExcludeComponents([component.componentId])}>Wyklucz cały komponent</Button></section>)}</div>}
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
        {plan.operations.length === 0 && <Callout severity="success" title="Plan nie zawiera operacji"><p>Wszystkie wykonywalne cele zostały wykluczone. Candidate, commit i push pozostają zablokowane.</p></Callout>}
        <div className="execution-grid">
          <Card className={["CANDIDATE_APPLIED", "PARTIAL", "COMMITTED", "PUSHED"].includes(state) ? "stage-card stage-card--done" : "stage-card"}><span className="stage-number">01</span><CheckCircle2 className="done-icon" /><h3>Candidate po XPath</h3><p>Backup encji → locki → live recheck → jedna operacja API po drugiej → validate.</p><Button variant="primary" loading={busy === "candidate"} disabled={!writeEnabled || !canApplyCandidate} onClick={() => plan.defaultPolicyOverride && plan.warnings.some((warning) => warning.includes("DEFAULT")) ? setConfirmAction("candidate") : onApplyCandidate()}>Zapisz Candidate przez API</Button></Card>
          <Card className={["COMMITTED", "PUSHED"].includes(state) ? "stage-card stage-card--done" : "stage-card"}><span className="stage-number">02</span><PackageCheck /><h3>Commit Panorama</h3><p>Osobny partial commit administratora. Przed startem zobaczysz ostrzeżenie z zakresem.</p><Button variant="primary" loading={busy === "commit"} disabled={!writeEnabled || !canCommit} onClick={() => setConfirmAction("commit")}>Commit</Button></Card>
          <Card className={state === "PUSHED" ? "stage-card stage-card--done" : "stage-card"}><span className="stage-number">03</span><CloudUpload /><h3>Push do urządzeń</h3><p>Osobny job tylko do device groups wynikających z planu.</p><div className="push-targets">{plan.affectedDeviceGroups.map((group) => <StatusPill key={group}>{group}</StatusPill>)}</div><Button variant="primary" loading={busy === "push"} disabled={!writeEnabled || !canPush} onClick={() => setConfirmAction("push")}>Validate & Push</Button></Card>
        </div>
        {executionJob && <ExecutionProgress job={executionJob} />}
        {executionSession?.jobs.length ? <Card className="jobs-card">{executionSession.jobs.map((job) => <div className="job-row" key={job.id}><div><StatusPill tone={job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning"}>{job.state}</StatusPill><div><strong>{job.kind.toUpperCase()} · {job.id}</strong><span>{job.message}</span></div></div><ProgressBar value={job.progress} label={`${job.progress}%`} /></div>)}</Card> : null}
      </section>

      <details className="analysis-details-drawer">
        <summary><span><GitCompareArrows size={18} /><span><strong>Szczegóły analizy, diff, ostrzeżenia i operacje API</strong><small>Jedno rozwijane okno · nie zasłania listy polityk</small></span></span><ChevronDown size={18} /></summary>
        <div className="analysis-details-content">
          <div className="analysis-summary-grid"><div><strong>Running ↔ Candidate</strong><span>{plan.diff.summary}</span><small>Natywne: {plan.diff.nativeEntries} · semantyczne: {plan.diff.semanticEntries}</small></div><div><strong>Device groups</strong><span>{plan.affectedDeviceGroups.join(", ") || "shared"}</span><small>Zakres push jest wyliczony z dotkniętych XPath.</small></div><div><strong>Bezpieczeństwo</strong><span>SHA256 · lock · per-XPath fingerprint</span><small>Candidate jest odczytywany live przed zapisem.</small></div></div>
          {plan.warnings.map((warning) => <Callout severity={warning.includes("DEFAULT") ? "warning" : warning.includes("Application Override") ? "warning" : "info"} title={warning.includes("DEFAULT") ? "DEFAULT — ochrona" : warning.includes("Application Override") ? "Application Override — read-only" : "Informacja z analizy"} key={warning}><p>{warning}</p></Callout>)}
          <div className="analysis-downloads"><Button icon={<Download size={15} />} onClick={() => onDownload("commands")}>Podgląd CLI</Button><Button icon={<Download size={15} />} onClick={() => onDownload("report")}>Raport</Button><Button icon={<Download size={15} />} onClick={() => onDownload("manifest")}>Manifest + backupy</Button></div>
          <div className="responsive-table operations-table"><table><thead><tr><th>#</th><th>API</th><th>Encja</th><th>Zakres</th><th>XPath / rollback</th></tr></thead><tbody>{filteredOperations.map((operation) => <tr key={operation.id}><td>{operation.order}</td><td><StatusPill tone={operation.action === "delete" ? "danger" : "warning"}>{operation.action.toUpperCase()}</StatusPill></td><td><strong>{operation.entityName}</strong><small>{operation.entityType}</small></td><td>{operation.scope}</td><td><code>{operation.xpath}</code><small><ShieldCheck size={12} /> {operation.inverseSummary}</small></td></tr>)}</tbody></table></div>
        </div>
      </details>

      <div className="safety-footer"><AlertOctagon size={18} /><span><strong>Restore jest ścieżkowy.</strong> Kliknij Restore przy konkretnym celu albo odtwórz całą sesję; closure zależności jest liczone z backupów.</span><ArrowRight size={18} /></div>

      {confirmAction && <div className="write-confirm-backdrop"><div className={`write-confirm ${confirmAction !== "commit" ? "write-confirm--critical" : ""}`} role="dialog" aria-modal="true"><div><AlertTriangle size={22} /><strong>{confirmAction === "candidate" ? "UWAGA: Candidate może naruszyć DEFAULT" : confirmAction === "commit" ? "Potwierdź commit do Panorama" : "UWAGA: potwierdź push do urządzeń"}</strong></div><p>{confirmAction === "candidate" ? "W tym planie jawnie włączono override. Candidate zapisze operacje, które mogą dotknąć polityki DEFAULT i jej zależności. Sprawdź XPath oraz zakres przed wykonaniem." : confirmAction === "commit" ? "Candidate zostanie utrwalony partial commitem bieżącego administratora. Przed zatwierdzeniem sprawdź pełną listę operacji poniżej; to nadal nie wykonuje push do firewalli." : `Zmiany zostaną wysłane do: ${plan.affectedDeviceGroups.join(", ") || "zakresu shared"}. Zweryfikuj zakres i stan urządzeń przed kontynuacją.`}</p>{confirmAction === "commit" && <div className="commit-review"><div className="commit-review__summary"><strong>{filteredOperations.length} operacji w przeglądzie</strong><span>{plan.affectedDeviceGroups.join(", ") || "shared"} · {plan.addresses.length} celów · {plan.addresses.reduce((sum, target) => sum + (target.references?.length ?? 0), 0)} referencji</span></div><div className="commit-review__list">{filteredOperations.map((operation) => <div key={operation.id}><StatusPill tone={operation.action === "delete" ? "danger" : "warning"}>{operation.action.toUpperCase()}</StatusPill><span><strong>{operation.entityName}</strong><small>{operation.entityType} · {operation.scope}</small><code>{operation.xpath}</code></span></div>)}</div></div>}<div><Button onClick={() => setConfirmAction(null)}>Anuluj</Button><Button variant={confirmAction !== "commit" ? "danger" : "primary"} onClick={() => { const action = confirmAction; setConfirmAction(null); if (action === "candidate") onApplyCandidate(); else if (action === "commit") onCommit(); else onPush(); }}>{confirmAction === "candidate" ? "Tak, zapisz Candidate" : confirmAction === "commit" ? "Tak, uruchom commit" : "Tak, wykonaj PUSH"}</Button></div></div></div>}
    </div>
  );
}
