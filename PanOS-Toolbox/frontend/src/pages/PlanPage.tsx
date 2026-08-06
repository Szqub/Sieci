import { useMemo, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Boxes,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  CloudUpload,
  Code2,
  Download,
  FileClock,
  GitCompareArrows,
  ListTree,
  Lock,
  PackageCheck,
  Radio,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { CapabilityStage, CleanupPlan, SessionState, ToolboxSession } from "../model";
import { formatDate, shortId, stageAllows } from "../model";
import { Button, Callout, Card, CardHeader, EmptyState, PageHeader, ProgressBar, StatCard, StatusPill, Toggle } from "../components/Primitives";

interface PlanPageProps {
  plan: CleanupPlan | null;
  executionSession: ToolboxSession | null;
  apiMaxStage: CapabilityStage;
  writeEnabled: boolean;
  busy: "candidate" | "commit" | "push" | "download" | null;
  error: string | null;
  onOpenCleanup: () => void;
  onApplyCandidate: () => void;
  onCommit: (allowUnisolated: boolean, allowFull: boolean) => void;
  onPush: () => void;
  onDownload: (artifact: "commands" | "report" | "manifest") => void;
}

const stateTone: Partial<Record<SessionState, "accent" | "success" | "danger" | "warning" | "info">> = {
  PLANNED: "info",
  WRITING_CANDIDATE: "warning",
  CANDIDATE_APPLIED: "warning",
  COMMITTING: "warning",
  COMMITTED: "accent",
  PUSHING: "warning",
  PUSHED: "success",
  FAILED: "danger",
  CONFLICT: "danger",
  PARTIAL: "warning",
  OUTCOME_UNKNOWN: "danger",
};

const decisionLabel = {
  process: "Do usunięcia",
  "skip-live": "Żywy — pominięty",
  "skip-error": "ICMP error — pominięty",
  "not-found": "Nie istnieje",
  blocked: "Blokada zależności — review",
};

const icmpTone = {
  responded: "success",
  timeout: "neutral",
  error: "danger",
  "not-run": "neutral",
} as const;

export function PlanPage({ plan, executionSession, apiMaxStage, writeEnabled, busy, error, onOpenCleanup, onApplyCandidate, onCommit, onPush, onDownload }: PlanPageProps) {
  const [tab, setTab] = useState<"addresses" | "operations">("addresses");
  const [expandedAddress, setExpandedAddress] = useState<string | null>(null);
  const [allowUnisolated, setAllowUnisolated] = useState(false);
  const [allowFull, setAllowFull] = useState(false);
  const state = executionSession?.state ?? plan?.state ?? "PLANNED";

  const stages = useMemo(() => [
    { id: "plan", label: "Plan", state: "PLANNED" as SessionState, icon: ListTree },
    { id: "candidate", label: "Candidate", state: "CANDIDATE_APPLIED" as SessionState, icon: ServerCog },
    { id: "commit", label: "Commit", state: "COMMITTED" as SessionState, icon: PackageCheck },
    { id: "push", label: "Push", state: "PUSHED" as SessionState, icon: CloudUpload },
  ], []);
  const stageIndex = state === "WRITING_CANDIDATE" || state === "CANDIDATE_APPLIED" || state === "PARTIAL" ? 1
    : state === "COMMITTING" || state === "COMMITTED" ? 2
      : state === "PUSHING" || state === "PUSHED" ? 3
        : 0;

  if (!plan) {
    return (
      <div className="page-stack">
        <PageHeader eyebrow="Workflow / Plan" title="Plan i wykonanie" description="Weryfikuj każdą mutację przed zapisaniem candidate." />
        <Card><EmptyState icon={<ListTree size={27} />} title="Nie ma jeszcze planu" description="Wklej IP lub nazwy encji i uruchom analizę. Ten ekran pokaże dokładne zależności, backupy i operacje odwrotne." action={<Button variant="primary" onClick={onOpenCleanup}>Utwórz plan</Button>} /></Card>
      </div>
    );
  }

  const candidateAllowed = stageAllows(apiMaxStage, "candidate");
  const commitAllowed = stageAllows(apiMaxStage, "commit");
  const pushAllowed = stageAllows(apiMaxStage, "push");
  const canApplyCandidate = state === "PLANNED";
  const canCommit = state === "CANDIDATE_APPLIED" || state === "PARTIAL";
  const canPush = state === "COMMITTED";

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow={`Session / ${shortId(plan.sessionId)}`}
        title="Plan zmian gotowy do przeglądu"
        description={`Utworzono ${formatDate(plan.createdAt)} · running config jest źródłem analizy, candidate jest sprawdzany ponownie przed zapisem.`}
        actions={<><StatusPill tone={stateTone[state] ?? "neutral"}>{state.replaceAll("_", " ")}</StatusPill><Button icon={<Download size={16} />} loading={busy === "download"} onClick={() => onDownload("commands")}>Pakiet CLI</Button></>}
      />

      {error && <Callout severity="danger" title="Etap nie został zakończony"><p>{error}</p></Callout>}

      <Card className="stage-rail-card">
        <div className="stage-rail">
          {stages.map((stage, index) => {
            const Icon = stage.icon;
            const done = index < stageIndex || state === "PUSHED";
            const active = index === stageIndex && state !== "PUSHED";
            return (
              <div key={stage.id} className={`${done ? "is-done" : ""} ${active ? "is-active" : ""}`}>
                <span className="stage-rail__icon">{done ? <Check size={17} /> : <Icon size={17} />}</span>
                <div><small>Etap {index + 1}</small><strong>{stage.label}</strong></div>
                {index < stages.length - 1 && <i />}
              </div>
            );
          })}
        </div>
      </Card>

      <div className="stats-grid stats-grid--6">
        <StatCard label="Wejście" value={plan.sourceCount} detail="celów" />
        <StatCard label="Do usunięcia" value={plan.processCount} detail={`${plan.operations.length} operacji`} tone="accent" />
        <StatCard label="Live" value={plan.skippedLiveCount} detail="pominięte" tone="success" />
        <StatCard label="ICMP error" value={plan.skippedErrorCount} detail="pominięte" tone={plan.skippedErrorCount ? "warning" : "neutral"} />
        <StatCard label="Nie istnieje" value={plan.notFoundCount} detail="zaraportowane" />
        <StatCard label="Recent Last Hit" value={plan.recentHitCount} detail="do weryfikacji" tone={plan.recentHitCount ? "danger" : "success"} />
      </div>

      <div className="plan-overview-grid">
        <Card>
          <CardHeader title="Running ↔ Candidate" description="Natywny change-summary oraz diff obsługiwanych namespace’ów." action={<GitCompareArrows size={20} />} />
          <div className="diff-panel">
            <div><span className={`diff-indicator ${plan.diff.nativeChanged ? "is-changed" : ""}`} /><p><strong>Panorama change-summary</strong><small>{plan.diff.nativeEntries} istniejących zmian</small></p></div>
            <div><span className={`diff-indicator ${plan.diff.semanticChanged ? "is-changed" : ""}`} /><p><strong>Diff semantyczny</strong><small>{plan.diff.semanticEntries} zmian w znanych namespace’ach</small></p></div>
          </div>
          <p className="diff-summary">{plan.diff.summary}</p>
          {plan.diff.diagnosticMismatch && <Callout severity="warning" title="Metody diffu są rozbieżne"><p>To ostrzeżenie diagnostyczne nie blokuje generatora. Przed zapisem dotknięte XPath zostaną sprawdzone ponownie.</p></Callout>}
        </Card>
        <Card>
          <CardHeader title="Zakres zmian" description="Device groups i zabezpieczenia sesji." action={<Boxes size={20} />} />
          <div className="dg-tags">{plan.affectedDeviceGroups.map((group) => <span key={group}>{group}</span>)}</div>
          <ul className="assurance-list">
            <li><ShieldCheck size={16} /><span>Pełny running i candidate z SHA256 przed pierwszym zapisem</span></li>
            <li><FileClock size={16} /><span>Backup encji i kolejności reguł w manifeście sesji</span></li>
            <li><Lock size={16} /><span>Fingerprint oraz config lock dla dotkniętych zakresów</span></li>
          </ul>
        </Card>
      </div>

      {plan.recentHitCount > 0 && <Callout severity="warning" title={`${plan.recentHitCount} polityk ma świeży Last Hit`}><p>Plan pozostaje dostępny, ale przed zapisaniem candidate zweryfikuj reguły oznaczone ikoną ostrzeżenia.</p></Callout>}
      {plan.warnings.map((warning) => <Callout severity="info" title="Informacja z analizy" key={warning}><p>{warning}</p></Callout>)}

      <Card className="review-card">
        <div className="review-tabs" role="tablist">
          <button className={tab === "addresses" ? "is-active" : ""} onClick={() => setTab("addresses")} role="tab"><Radio size={16} /> Cele <span>{plan.addresses.length}</span></button>
          <button className={tab === "operations" ? "is-active" : ""} onClick={() => setTab("operations")} role="tab"><Code2 size={16} /> Operacje API <span>{plan.operations.length}</span></button>
          <div className="review-tabs__actions"><Button variant="ghost" icon={<Download size={15} />} onClick={() => onDownload("report")}>Raport</Button><Button variant="ghost" icon={<Download size={15} />} onClick={() => onDownload("manifest")}>Manifest</Button></div>
        </div>

        {tab === "addresses" ? (
          <div className="responsive-table plan-table">
            <table>
              <thead><tr><th>LP</th><th>Cel</th><th>ICMP</th><th>Last Hit polityki</th><th>Referencje</th><th>Decyzja</th><th /></tr></thead>
              <tbody>
                {plan.addresses.map((address, index) => {
                  const expanded = expandedAddress === address.ip;
                  return [
                    <tr key={address.ip} className={address.recentLastHit ? "row-warning" : ""}>
                      <td>{index + 1}</td>
                      <td><div className="entity-cell"><strong>{address.label ?? address.ip}</strong><small>{address.targetType ?? "ip"} · {address.objectNames.join(", ") || "brak dopasowania"}</small></div></td>
                      <td><StatusPill tone={icmpTone[address.icmp]}>{address.icmp}{address.icmp === "responded" && " · live"}</StatusPill></td>
                      <td>{address.recentLastHit ? <span className="recent-hit"><AlertTriangle size={14} /> {formatDate(address.lastHit)}</span> : <span className="muted-value">{address.lastHitStatus ? `${address.lastHitStatus} · ${formatDate(address.lastHit)}` : "—"}</span>}</td>
                      <td><span className="reference-count">{address.references.length}</span></td>
                      <td><StatusPill tone={address.decision === "process" ? "accent" : address.decision === "skip-live" ? "success" : address.decision === "skip-error" ? "danger" : address.decision === "blocked" ? "warning" : "neutral"}>{decisionLabel[address.decision]}</StatusPill></td>
                      <td><button className="table-expand" disabled={!address.references.length} onClick={() => setExpandedAddress(expanded ? null : address.ip)} aria-label={`Pokaż referencje ${address.ip}`}>{expanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}</button></td>
                    </tr>,
                    expanded && <tr className="expanded-row" key={`${address.ip}-details`}><td colSpan={7}><div className="reference-list">{address.references.map((ref) => <div key={ref.id}><ListTree size={16} /><div><strong>{ref.name}</strong><span>{ref.deviceGroup} · {ref.rulebase}-rulebase · {ref.policyType} · {ref.field}</span><code>{ref.path}</code></div></div>)}</div></td></tr>,
                  ];
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="responsive-table operations-table">
            <table>
              <thead><tr><th>#</th><th>Operacja</th><th>Encja</th><th>Zakres</th><th>Zmiana / rollback</th><th>Fingerprint</th></tr></thead>
              <tbody>{plan.operations.map((operation) => <tr key={operation.id}><td>{operation.order}</td><td><StatusPill tone={operation.action === "delete" ? "danger" : "warning"} dot={false}>{operation.action.toUpperCase()}</StatusPill></td><td><div className="entity-cell"><strong>{operation.entityName}</strong><small>{operation.entityType}</small></div></td><td>{operation.scope}</td><td><div className="operation-copy"><strong>{operation.summary}</strong><small><ShieldCheck size={13} /> {operation.inverseSummary}</small><code>{operation.xpath}</code></div></td><td><code>{operation.fingerprint}</code></td></tr>)}</tbody>
            </table>
          </div>
        )}
      </Card>

      <section className="execution-section">
        <div className="execution-heading"><div><span className="eyebrow">Staged execution</span><h2>Wykonanie kontrolowane</h2><p>Każdy etap kończy się osobnym wynikiem. Commit ani push nie uruchamiają się automatycznie.</p></div><StatusPill tone={writeEnabled ? "danger" : "neutral"}>{writeEnabled ? "API write aktywny" : "Generator only"}</StatusPill></div>

        {!writeEnabled && <Callout severity="info" title="Zapis przez API jest wyłączony"><p>Plan, raporty i komendy CLI są kompletne. Aby użyć przycisków wykonawczych, profil musi zezwalać na dany poziom i runtime toggle w górnym pasku musi być włączony.</p></Callout>}

        <div className="execution-grid">
          <Card className={state === "CANDIDATE_APPLIED" || state === "PARTIAL" || state === "COMMITTED" || state === "PUSHED" ? "stage-card stage-card--done" : "stage-card"}>
            <span className="stage-number">01</span>
            <CardHeader title="Zapisz Candidate" description="Backup → lock → recheck XPath → patch → validate" action={state === "CANDIDATE_APPLIED" || state === "PARTIAL" || state === "COMMITTED" || state === "PUSHED" ? <CheckCircle2 className="done-icon" /> : <ServerCog />} />
            <ul><li>Nie wykonuje commit</li><li>Cofa zastosowane mutacje przy błędzie</li><li>Tworzy dziennik i inverse patch</li></ul>
            {!candidateAllowed && <span className="stage-blocked"><Lock size={14} /> Profil read-only blokuje etap</span>}
            <Button variant="primary" loading={busy === "candidate"} disabled={!writeEnabled || !candidateAllowed || !canApplyCandidate} onClick={onApplyCandidate}>Zapisz i zwaliduj Candidate</Button>
          </Card>

          <Card className={state === "COMMITTED" || state === "PUSHED" ? "stage-card stage-card--done" : "stage-card"}>
            <span className="stage-number">02</span>
            <CardHeader title="Commit do Panorama" description="Partial commit operatora; bez push do firewalli" action={state === "COMMITTED" || state === "PUSHED" ? <CheckCircle2 className="done-icon" /> : <PackageCheck />} />
            <div className="risk-options">
              <Toggle checked={allowUnisolated} onChange={(value) => { setAllowUnisolated(value); if (!value) setAllowFull(false); }} label="Pozwól na nieizolowany partial commit" description="Może objąć inne zmiany tego samego administratora." danger />
              <Toggle checked={allowFull} onChange={(value) => { setAllowFull(value); if (value) setAllowUnisolated(true); }} label="Pozwól na full commit" description="Najwyższe ryzyko: obejmuje cały bieżący candidate." danger />
            </div>
            {(allowUnisolated || allowFull) && <div className="critical-warning"><ShieldAlert size={17} /><span><strong>Rozszerzony zakres commit</strong>Zostanie trwale zapisany w manifeście audytowym.</span></div>}
            {!commitAllowed && <span className="stage-blocked"><Lock size={14} /> Profil nie zezwala na commit</span>}
            {commitAllowed && !allowUnisolated && <span className="stage-blocked"><ShieldAlert size={14} /> Potwierdź zakres same-admin przez przełącznik Unisolated</span>}
            <Button variant={allowFull ? "danger" : "primary"} loading={busy === "commit"} disabled={!writeEnabled || !commitAllowed || !canCommit || !allowUnisolated} onClick={() => onCommit(allowUnisolated, allowFull)}>Uruchom {allowFull ? "full" : "partial"} commit</Button>
          </Card>

          <Card className={state === "PUSHED" ? "stage-card stage-card--done" : "stage-card"}>
            <span className="stage-number">03</span>
            <CardHeader title="Push do urządzeń" description="Osobny job tylko dla dotkniętych device groups" action={state === "PUSHED" ? <CheckCircle2 className="done-icon" /> : <CloudUpload />} />
            <div className="push-targets">{plan.affectedDeviceGroups.map((group) => <label key={group} title="Zakres wynika z dotkniętych ścieżek i hierarchii DG"><input type="checkbox" checked readOnly aria-label={`${group} — wymagany zakres push`} /><span><CircleDot size={13} />{group}</span></label>)}</div>
            {!pushAllowed && <span className="stage-blocked"><Lock size={14} /> Profil nie zezwala na push</span>}
            <Button variant="primary" loading={busy === "push"} disabled={!writeEnabled || !pushAllowed || !canPush} onClick={onPush}>Validate & Push</Button>
          </Card>
        </div>

        {executionSession?.jobs.length ? (
          <Card className="jobs-card"><CardHeader title="Joby Panorama" description="Status operacji asynchronicznych odczytywany do stanu FIN." />{executionSession.jobs.map((job) => <div className="job-row" key={job.id}><div><StatusPill tone={job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning"}>{job.state}</StatusPill><div><strong>{job.kind.toUpperCase()} · Job {job.id}</strong><span>{job.message}</span></div></div><ProgressBar value={job.progress} label={`${job.progress}%`} /></div>)}</Card>
        ) : null}

        {(state === "FAILED" || state === "CONFLICT" || state === "OUTCOME_UNKNOWN") && <Callout severity="danger" title="Wykonanie wymaga uwagi"><p>Stan jest terminalny dla tej sesji. Sprawdź live status, dziennik i pakiet konfliktów, a następnie wykonaj nowy plan — ponowienie mutacji nie jest dostępne.</p></Callout>}
        {state === "PARTIAL" && <Callout severity="warning" title="Candidate zawiera bezpieczny subset"><p>Co najmniej jeden komponent został pominięty z powodu konfliktu. Możesz świadomie commitować zastosowany subset po przejrzeniu raportu konfliktów.</p></Callout>}
        {state === "PUSHED" && <Callout severity="success" title="Cleanup zakończony"><p>Candidate, commit i push zakończyły się poprawnie. Sesja zawiera pełny manifest potrzebny do Emergency Restore.</p></Callout>}
      </section>

      <div className="safety-footer"><AlertOctagon size={18} /><span><strong>Rollback nie ładuje pełnego configu.</strong> Restore porównuje base, expected i current oraz dotyka wyłącznie ścieżek zapisanych w sesji.</span><ArrowRight size={18} /></div>
    </div>
  );
}
