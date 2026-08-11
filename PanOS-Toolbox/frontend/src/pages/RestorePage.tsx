import { useEffect, useMemo, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  CloudUpload,
  ClipboardCopy,
  Download,
  Eye,
  FileArchive,
  FileText,
  GitMerge,
  History,
  PackageCheck,
  RefreshCcw,
  RotateCcw,
  Search,
  ServerCog,
  ShieldCheck,
  ShieldX,
  Terminal,
  X,
} from "lucide-react";
import type { ExecutionJob, RestorePlan, SessionArtifact, ToolboxSession } from "../model";
import { formatDate, shortId } from "../model";
import { ExecutionProgress } from "../components/ExecutionProgress";
import { Button, Callout, Card, CardHeader, EmptyState, PageHeader, StatCard, StatusPill } from "../components/Primitives";

interface RestorePageProps {
  query: string;
  onQueryChange: (query: string) => void;
  plan: RestorePlan | null;
  executionSession: ToolboxSession | null;
  executionJob: ExecutionJob | null;
  writeEnabled: boolean;
  connected: boolean;
  busy: "plan" | "candidate" | "commit" | "push" | "download" | null;
  error: string | null;
  onCreatePlan: (mode: "target" | "session") => void;
  onApplyCandidate: () => void;
  onCommit: () => void;
  onPush: () => void;
  onDownloadConflicts: () => void;
  onViewArtifact: (artifact: string) => Promise<string>;
  onDownloadArtifact: (artifact: string) => void;
  onOpenConnection: () => void;
  onOpenWarnings: () => void;
}

export function RestorePage({ query, onQueryChange, plan, executionSession, executionJob, writeEnabled, connected, busy, error, onCreatePlan, onApplyCandidate, onCommit, onPush, onDownloadConflicts, onViewArtifact, onDownloadArtifact, onOpenConnection, onOpenWarnings }: RestorePageProps) {
  const sessionQuery = (value: string) => !value.includes("\n") && /^(session-|cleanup-)/.test(value.trim());
  const [mode, setMode] = useState<"target" | "session">(() => sessionQuery(query) ? "session" : "target");
  const [confirmAction, setConfirmAction] = useState<"commit" | "push" | null>(null);
  const [artifactViewer, setArtifactViewer] = useState<{ file: string; content: string; loading: boolean; error?: string } | null>(null);
  const [copiedArtifact, setCopiedArtifact] = useState<string | null>(null);
  const [confirmConflictCopy, setConfirmConflictCopy] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  useEffect(() => { setMode(sessionQuery(query) ? "session" : "target"); }, [query]);

  const state = executionSession?.state ?? plan?.state ?? "PLANNED";
  const safeEntities = useMemo(() => plan?.entities.filter((entity) => entity.outcome !== "conflict") ?? [], [plan]);
  const conflicts = useMemo(() => plan?.entities.filter((entity) => entity.outcome === "conflict") ?? [], [plan]);
  const candidateDone = ["RESTORED", "PARTIAL", "COMMITTING", "COMMITTED", "PUSHING", "PUSHED"].includes(state);
  const commitDone = ["COMMITTED", "PUSHING", "PUSHED"].includes(state);
  const artifacts = useMemo(() => {
    const catalog = new Map<string, SessionArtifact>();
    for (const artifact of plan?.artifacts ?? []) catalog.set(artifact.file, artifact);
    for (const artifact of executionSession?.artifacts ?? []) catalog.set(artifact.file, artifact);
    for (const artifact of executionJob?.session?.artifacts ?? []) catalog.set(artifact.file, artifact);
    return [...catalog.values()];
  }, [executionJob?.session?.artifacts, executionSession?.artifacts, plan?.artifacts]);
  const activeHandMode = artifacts.find((artifact) => artifact.kind === "handmode-cli-active");
  const rollbackHandMode = artifacts.find((artifact) => artifact.kind === "handmode-cli-rollback") ?? artifacts.find((artifact) => artifact.file === "handmode_rollback.txt");
  const handModeInstructions = artifacts.find((artifact) => artifact.kind === "handmode-instructions") ?? artifacts.find((artifact) => artifact.file === "handmode_instructions.txt");
  const conflictHandMode = artifacts.find((artifact) => artifact.kind === "handmode-cli-conflict-restore-manual-review") ?? artifacts.find((artifact) => artifact.file === "handmode_conflict_restore_commands.txt");
  const conflictRollback = artifacts.find((artifact) => artifact.kind === "handmode-cli-conflict-restore-rollback") ?? artifacts.find((artifact) => artifact.file === "handmode_conflict_restore_rollback.txt");
  const conflictInstructions = artifacts.find((artifact) => artifact.kind === "handmode-conflict-restore-instructions") ?? artifacts.find((artifact) => artifact.file === "handmode_conflict_restore_instructions.txt");
  const handModeBlocked = Boolean(plan && plan.operations.length > 0 && (!activeHandMode || activeHandMode.sizeBytes === 0));

  const openArtifact = async (file: string) => {
    setArtifactViewer({ file, content: "", loading: true });
    try {
      const content = await onViewArtifact(file);
      setArtifactViewer({ file, content, loading: false });
    } catch (viewerError) {
      setArtifactViewer({ file, content: "", loading: false, error: viewerError instanceof Error ? viewerError.message : "Nie można wyświetlić pliku." });
    }
  };

  const copyArtifact = async (file: string) => {
    setCopyError(null);
    try {
      const content = artifactViewer?.file === file && !artifactViewer.loading && !artifactViewer.error
        ? artifactViewer.content
        : await onViewArtifact(file);
      if (!navigator.clipboard?.writeText) throw new Error("Przeglądarka nie udostępnia schowka. Użyj Wyświetl i skopiuj z podglądu albo Pobierz TXT.");
      await navigator.clipboard.writeText(content);
      setCopiedArtifact(file);
      window.setTimeout(() => setCopiedArtifact((current) => current === file ? null : current), 1800);
    } catch (clipboardError) {
      setCopyError(clipboardError instanceof Error ? clipboardError.message : "Nie udało się skopiować komend.");
    }
  };

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
          <div className="segmented-control segmented-control--large"><button className={mode === "target" ? "is-active" : ""} onClick={() => setMode("target")}><Search size={15} /> Cel / IP / polityka</button><button className={mode === "session" ? "is-active" : ""} onClick={() => setMode("session")}><History size={15} /> Session ID</button></div>
          <div className="restore-input"><textarea rows={mode === "target" ? 3 : 1} value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder={mode === "target" ? "Po jednym celu na linię: IP, object:NAZWA, group:NAZWA lub policy:NAZWA" : "session-YYYYMMDDT…"} spellCheck={false} /><Button variant="primary" loading={busy === "plan"} disabled={!connected || !query.trim()} onClick={() => onCreatePlan(mode)} icon={<GitMerge size={17} />}>Przelicz Restore</Button></div>
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

          {plan.warnings.length > 0 && <div className="notice-actions"><button type="button" className="inline-notice-link" onClick={onOpenWarnings}><AlertTriangle size={15} /><span><strong>{plan.warnings.length} uwag z Restore</strong><small>Konflikty i szczegóły są w panelu Uwagi</small></span></button><Button icon={<Download size={15} />} onClick={onDownloadConflicts} loading={busy === "download"}>Pakiet ręczny</Button></div>}

          <Card className="handmode-card">
            <div className="handmode-card__header">
              <span className="handmode-card__icon"><Terminal size={22} /></span>
              <div><span className="eyebrow">Emergency Restore / PAN-OS CLI</span><h2>Hand Mode — ręczne odtworzenie</h2><p>Bezpieczny subset jest zgodny z inverse PatchSetem Restore. Pliki zawierają tylko komendy trybu <code>configure (#)</code>; commit i push wykonujesz osobno.</p></div>
              <StatusPill tone={handModeBlocked ? "danger" : plan.operations.length ? "success" : "info"}>{handModeBlocked ? "CLI BLOCK" : plan.operations.length ? "CLI READY" : "BRAK SAFE MUTATIONS"}</StatusPill>
            </div>
            {copyError && <Callout severity="danger" title="Nie udało się skopiować"><p>{copyError}</p></Callout>}
            <div className="handmode-command-grid">
              <section>
                <div><strong>Bezpieczny Restore</strong><small><code>commands.txt</code> · tylko komponenty dopuszczone przez merge trójstronny</small></div>
                <div>{activeHandMode && <><Button icon={<Eye size={15} />} onClick={() => void openArtifact(activeHandMode.file)}>Wyświetl</Button><Button variant="primary" icon={<ClipboardCopy size={15} />} disabled={handModeBlocked} onClick={() => void copyArtifact(activeHandMode.file)}>{copiedArtifact === activeHandMode.file ? "Skopiowano" : "Kopiuj wszystko"}</Button><Button icon={<Download size={15} />} onClick={() => onDownloadArtifact(activeHandMode.file)}>Pobierz TXT</Button></>}{rollbackHandMode && <Button variant="ghost" icon={<RotateCcw size={15} />} onClick={() => void openArtifact(rollbackHandMode.file)}>Cofnięcie Restore</Button>}</div>
              </section>
              {handModeInstructions && <section className="handmode-instructions"><div><strong>Instrukcja i status renderera</strong><small>READY/BLOCK, liczba komend, ostrzeżenia XML i kolejność wykonania</small></div><div><Button variant="ghost" icon={<Eye size={15} />} onClick={() => void openArtifact(handModeInstructions.file)}>Wyświetl instrukcję</Button><Button variant="ghost" icon={<Download size={15} />} onClick={() => onDownloadArtifact(handModeInstructions.file)}>Pobierz</Button></div></section>}
            </div>
            {handModeBlocked && <Callout severity="danger" title="Hand Mode Restore zablokowany"><p>Co najmniej jedna operacja nie ma bezpiecznego odpowiednika CLI. <code>commands.txt</code> jest celowo pusty, więc nie da się skopiować niepełnego restore. Dokładny powód znajduje się w instrukcji.</p></Callout>}
            {conflictHandMode && <div className="handmode-excluded">
              <AlertOctagon size={20} />
              <span><strong>Osobny zestaw: komponenty konfliktowe</strong><small>Three-way merge odrzucił je z bezpiecznego Restore. Nie łącz tego pliku z <code>commands.txt</code> bez sprawdzenia aktualnego configu, <code>manual_conflicts.json</code> i pełnego diffu.</small></span>
              <div><Button variant="danger" icon={<Eye size={15} />} onClick={() => void openArtifact(conflictHandMode.file)}>Wyświetl konflikty</Button><Button variant="danger" icon={<ClipboardCopy size={15} />} disabled={conflictHandMode.sizeBytes === 0} onClick={() => setConfirmConflictCopy(conflictHandMode.file)}>Kopiuj konflikty…</Button><Button icon={<Download size={15} />} onClick={() => onDownloadArtifact(conflictHandMode.file)}>Pobierz</Button>{conflictRollback && <Button variant="ghost" icon={<RotateCcw size={15} />} onClick={() => void openArtifact(conflictRollback.file)}>Rollback konfliktów</Button>}{conflictInstructions && <Button variant="ghost" icon={<FileText size={15} />} onClick={() => void openArtifact(conflictInstructions.file)}>Instrukcja konfliktów</Button>}</div>
            </div>}
          </Card>

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
            <div className="execution-heading"><div><span className="eyebrow">Recovery execution</span><h2>Odtworzenie etapowe</h2><p>Inverse patch trafia najpierw do candidate. Commit i push pozostają osobnymi decyzjami.</p></div><StatusPill tone={writeEnabled ? "success" : "info"}>{writeEnabled ? "WRITE aktywny" : "READ ONLY"}</StatusPill></div>
            {conflicts.length > 0 && <Callout severity="warning" title={`${plan.conflictComponentCount} komponent konfliktowy zostanie pominięty`}><p>Safe subset obejmuje wyłącznie komponenty niezależne. Dla konfliktów powstał osobny raport i pakiet ręczny.</p></Callout>}
            <div className="restore-stage-grid">
              <Card className={candidateDone ? "restore-stage restore-stage--done" : "restore-stage"}>
                <span>1</span><ServerCog size={21} /><h3>Restore Candidate</h3><p>Powtórny fingerprint, backup bieżącego stanu, inverse patch i validation.</p>
                <Button variant="primary" loading={busy === "candidate"} disabled={!writeEnabled || state !== "PLANNED"} onClick={onApplyCandidate}>Zastosuj safe subset</Button>
              </Card>
              <Card className={commitDone ? "restore-stage restore-stage--done" : "restore-stage"}>
                <span>2</span><PackageCheck size={21} /><h3>Commit Restore</h3><p>Partial commit operatora na Panorama. Ryzykowne rozszerzenia wymagają osobnej zgody.</p>
                <Button variant="primary" loading={busy === "commit"} disabled={!writeEnabled || (state !== "RESTORED" && state !== "PARTIAL")} onClick={() => setConfirmAction("commit")}>Commit Restore</Button>
              </Card>
              <Card className={state === "PUSHED" ? "restore-stage restore-stage--done" : "restore-stage"}>
                <span>3</span><CloudUpload size={21} /><h3>Push Restore</h3><p>Push wyłącznie do device groups wynikających z bezpiecznego closure.</p>
                <div className="restore-targets">{plan.affectedDeviceGroups.map((scope) => <StatusPill key={scope} tone="neutral">{scope}</StatusPill>)}</div>
                <Button variant="primary" loading={busy === "push"} disabled={!writeEnabled || state !== "COMMITTED"} onClick={() => setConfirmAction("push")}>Validate & Push Restore</Button>
              </Card>
            </div>
            {executionJob && <ExecutionProgress job={executionJob} />}
            {state === "RESTORED" ? <Callout severity="success" title="Restore zapisany do Candidate"><p>Safe subset został zastosowany i zwalidowany. Commit ani push nie zostały jeszcze uruchomione.</p></Callout> : null}
            {state === "PARTIAL" ? <Callout severity="warning" title="Częściowy Restore zapisany do Candidate"><p>Bezpieczne komponenty zostały zastosowane; konfliktowe komponenty pominięto. Po przejrzeniu pakietu ręcznego możesz commitować safe subset.</p></Callout> : null}
            {state === "PUSHED" ? <Callout severity="success" title="Restore zakończony"><p>Bezpieczne komponenty zostały odtworzone. Zmiany niezależne pozostały nietknięte, a konflikty są dostępne w pakiecie ręcznym.</p></Callout> : null}
          </section>

          <div className="restore-policy"><ShieldCheck size={20} /><div><strong>Pełny backup jest tylko źródłem prawdy</strong><p>Toolbox nie wywoła automatycznego load config, nawet podczas Emergency Restore. Każdy zapis jest ścieżkowym patchem z operacją odwrotną.</p></div><AlertTriangle size={19} /></div>
          {confirmAction && <div className="write-confirm-backdrop"><div className={`write-confirm ${confirmAction === "push" ? "write-confirm--critical" : ""}`} role="dialog" aria-modal="true"><div><AlertTriangle size={22} /><strong>{confirmAction === "commit" ? "Potwierdź commit Restore" : "UWAGA: potwierdź push Restore"}</strong></div><p>{confirmAction === "commit" ? "Bezpieczny subset Restore zostanie utrwalony partial commitem. Push nie uruchomi się automatycznie." : `Odtworzone zmiany zostaną wysłane do: ${plan.affectedDeviceGroups.join(", ") || "shared"}.`}</p><div><Button onClick={() => setConfirmAction(null)}>Anuluj</Button><Button variant={confirmAction === "push" ? "danger" : "primary"} onClick={() => { const action = confirmAction; setConfirmAction(null); if (action === "commit") onCommit(); else onPush(); }}>{confirmAction === "commit" ? "Uruchom commit" : "Wykonaj PUSH"}</Button></div></div></div>}
          {confirmConflictCopy && <div className="write-confirm-backdrop"><div className="write-confirm write-confirm--critical" role="dialog" aria-modal="true" aria-labelledby="conflict-handmode-title">
            <div><AlertOctagon size={22} /><strong id="conflict-handmode-title">Kopiujesz konfliktowy Restore</strong></div>
            <p>Te komendy zostały jawnie odrzucone z bezpiecznego merge. Mogą nadpisać późniejszą zmianę operatora albo odtworzyć nieaktualną zależność. Najpierw porównaj je z aktualnym configiem i pakietem konfliktów.</p>
            <div><Button onClick={() => setConfirmConflictCopy(null)}>Anuluj</Button><Button variant="danger" onClick={() => { const file = confirmConflictCopy; setConfirmConflictCopy(null); void copyArtifact(file); }}>Rozumiem — kopiuj konfliktowy Restore</Button></div>
          </div></div>}
          {artifactViewer && <div className="artifact-viewer-backdrop"><div className="artifact-viewer" role="dialog" aria-modal="true" aria-label={`Podgląd ${artifactViewer.file}`}>
            <header><div><FileText size={19} /><span><strong>{artifactViewer.file}</strong><small>Pełny plik sesji · tylko do odczytu</small></span></div><div>{!artifactViewer.loading && !artifactViewer.error && <Button variant="ghost" icon={<ClipboardCopy size={14} />} onClick={() => artifactViewer.file === conflictHandMode?.file ? setConfirmConflictCopy(artifactViewer.file) : void copyArtifact(artifactViewer.file)}>{copiedArtifact === artifactViewer.file ? "Skopiowano" : "Kopiuj"}</Button>}<Button variant="ghost" icon={<Download size={14} />} onClick={() => onDownloadArtifact(artifactViewer.file)}>Pobierz</Button><button onClick={() => setArtifactViewer(null)} aria-label="Zamknij podgląd"><X size={19} /></button></div></header>
            {artifactViewer.loading ? <div className="artifact-viewer-loading"><ServerCog className="spin" size={22} /><span>Pobieranie pliku do podglądu…</span></div> : artifactViewer.error ? <Callout severity="danger" title="Nie można wyświetlić pliku"><p>{artifactViewer.error}</p></Callout> : <pre>{artifactViewer.content}</pre>}
          </div></div>}
        </>
      )}
    </div>
  );
}
