import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ChevronRight,
  Clock3,
  CloudUpload,
  ClipboardCopy,
  Database,
  Download,
  FileArchive,
  FileText,
  History,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldCheck,
  SquareTerminal,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { HistoryIssue, HistoryMutation, SessionState, ToolboxSession } from "../model";
import { formatDate, shortId } from "../model";
import { Button, Callout, Card, EmptyState, PageHeader, ProgressBar, StatusPill } from "../components/Primitives";

interface HistoryPageProps {
  sessions: ToolboxSession[];
  selected: ToolboxSession | null;
  storage: string;
  issues: HistoryIssue[];
  connected: boolean;
  busy: boolean;
  error: string | null;
  onRefresh: () => void;
  onSelect: (session: ToolboxSession) => void;
  onRestore: (session: ToolboxSession) => void;
  onRestoreTargets: (targets: string[]) => void;
  onDownloadBundle: (session: ToolboxSession) => void;
  onViewArtifact: (sessionId: string, artifact: string) => Promise<string>;
  onDownloadArtifact: (sessionId: string, artifact: string) => void;
  onMaterializeHandMode: (session: ToolboxSession) => void;
  onReconcileExternal: (session: ToolboxSession) => void;
}

interface ArtifactViewer {
  sessionId: string;
  file: string;
  loading: boolean;
  content?: string;
  error?: string;
}

const sessionTone: Partial<Record<SessionState, "neutral" | "accent" | "success" | "warning" | "danger" | "info">> = {
  PLANNED: "info", WRITING_CANDIDATE: "warning", CANDIDATE_APPLIED: "warning", COMMITTING: "warning", COMMITTED: "accent", PUSHING: "warning", PUSHED: "success", RESTORING: "warning", RESTORED: "success", PARTIAL: "warning", FAILED: "danger", CONFLICT: "danger", OUTCOME_UNKNOWN: "danger",
};

const executionLabel: Record<HistoryMutation["executionStatus"], string> = {
  planned: "tylko plan",
  "candidate-applied": "Candidate wykonany",
  committed: "commit wykonany",
  pushed: "push wykonany",
  restored: "Restore wykonany",
  partial: "wykonano częściowo",
};

const executionTone: Record<HistoryMutation["executionStatus"], "info" | "warning" | "accent" | "success"> = {
  planned: "info",
  "candidate-applied": "warning",
  committed: "accent",
  pushed: "success",
  restored: "success",
  partial: "warning",
};

function exactDate(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("pl-PL", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

function queryTokens(value: string): string[] {
  return value.trim().toLocaleLowerCase("pl-PL").split(/\s+/).filter(Boolean);
}

function containsTokens(values: Array<string | undefined>, tokens: string[]): boolean {
  if (!tokens.length) return true;
  const haystack = values.filter(Boolean).join(" ").toLocaleLowerCase("pl-PL");
  return tokens.every((token) => haystack.includes(token));
}

function itemMatches(item: HistoryMutation, tokens: string[]): boolean {
  return containsTokens([
    item.entityName,
    item.entityKey,
    item.entityType,
    item.scope,
    item.rulebase,
    item.policyType,
    item.xpath,
    ...item.targets,
    ...item.searchValues,
  ], tokens);
}

function sessionMatches(session: ToolboxSession, tokens: string[]): boolean {
  return containsTokens([
    session.id,
    session.description,
    session.operator,
    session.panoramaHost,
    session.state,
    ...session.affectedDeviceGroups,
    ...(session.targets ?? []),
    ...(session.searchValues ?? []),
  ], tokens) || (session.historyItems ?? []).some((item) => itemMatches(item, tokens));
}

export function HistoryPage({
  sessions,
  selected,
  storage,
  issues,
  connected,
  busy,
  error,
  onRefresh,
  onSelect,
  onRestore,
  onRestoreTargets,
  onDownloadBundle,
  onViewArtifact,
  onDownloadArtifact,
  onMaterializeHandMode,
  onReconcileExternal,
}: HistoryPageProps) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | "cleanup" | "restore">("all");
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
  const [confirmReconcile, setConfirmReconcile] = useState(false);
  const [artifactViewer, setArtifactViewer] = useState<ArtifactViewer | null>(null);
  const [copiedArtifact, setCopiedArtifact] = useState<string | null>(null);
  const [confirmRiskyCopy, setConfirmRiskyCopy] = useState<{ sessionId: string; file: string } | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const tokens = useMemo(() => queryTokens(query), [query]);
  const filtered = useMemo(() => sessions.filter((session) => {
    if (kind !== "all" && session.kind !== kind) return false;
    return sessionMatches(session, tokens);
  }), [sessions, tokens, kind]);
  const active = filtered.find((session) => session.id === selected?.id) ?? filtered[0] ?? null;
  const activeItems = useMemo(() => {
    if (!active) return [];
    const items = active.historyItems ?? [];
    if (!tokens.length) return items;
    return items.filter((item) => itemMatches(item, tokens));
  }, [active, tokens]);
  const totalMatches = useMemo(() => filtered.reduce((count, session) => {
    if (!tokens.length) return count + (session.historyItems?.length ?? 0);
    return count + (session.historyItems ?? []).filter((item) => itemMatches(item, tokens)).length;
  }, 0), [filtered, tokens]);
  const latestRestorable = sessions.find((session) => session.kind === "cleanup" && session.canRestore)?.id;
  const activeArtifacts = active?.artifacts ?? [];
  const activeHandMode = activeArtifacts.find((artifact) => artifact.kind === "handmode-cli-active");
  const activeRollback = activeArtifacts.find((artifact) => artifact.kind === "handmode-cli-rollback");
  const activeInstructions = activeArtifacts.find((artifact) => artifact.kind === "handmode-instructions");
  const riskyHandMode = activeArtifacts.filter((artifact) => artifact.kind === "handmode-cli-excluded-manual-review" || artifact.kind === "handmode-cli-conflict-restore-manual-review");

  useEffect(() => {
    setSelectedTargets(new Set());
    setConfirmReconcile(false);
    setConfirmRiskyCopy(null);
    setCopyError(null);
  }, [active?.id]);

  const toggleTarget = (target: string) => setSelectedTargets((current) => {
    const next = new Set(current);
    if (next.has(target)) next.delete(target); else next.add(target);
    return next;
  });

  const openArtifact = async (sessionId: string, file: string) => {
    setArtifactViewer({ sessionId, file, loading: true });
    try {
      const content = await onViewArtifact(sessionId, file);
      setArtifactViewer({ sessionId, file, loading: false, content });
    } catch (viewError) {
      setArtifactViewer({ sessionId, file, loading: false, error: viewError instanceof Error ? viewError.message : "Nie można odczytać pliku." });
    }
  };

  const copyArtifact = async (sessionId: string, file: string) => {
    setCopyError(null);
    try {
      const content = artifactViewer?.sessionId === sessionId && artifactViewer.file === file && !artifactViewer.loading && !artifactViewer.error
        ? artifactViewer.content ?? ""
        : await onViewArtifact(sessionId, file);
      if (!navigator.clipboard?.writeText) throw new Error("Schowek jest niedostępny. Użyj Wyświetl i skopiuj z podglądu albo Pobierz TXT.");
      await navigator.clipboard.writeText(content);
      setCopiedArtifact(`${sessionId}:${file}`);
      window.setTimeout(() => setCopiedArtifact((current) => current === `${sessionId}:${file}` ? null : current), 1800);
    } catch (clipboardError) {
      setCopyError(clipboardError instanceof Error ? clipboardError.message : "Nie udało się skopiować pliku.");
    }
  };

  return <div className="page-stack history-design-page">
    <PageHeader
      eyebrow="Operations / Offline history"
      title="Historia zmian, backup i szybki Restore"
      description="Lokalny indeks działa bez logowania do Panoramy. Szuka po IP, polityce, obiekcie, grupie, DG, XPath i session ID oraz pokazuje, czy zmiana była tylko planem, czy została wykonana."
      actions={<><StatusPill tone={connected ? "success" : "info"}>{connected ? "Panorama online" : "Historia offline"}</StatusPill><Button onClick={onRefresh} loading={busy} icon={<RefreshCw size={16} />}>Odśwież indeks</Button></>}
    />
    <Callout severity={connected ? "success" : "info"} title={connected ? "Historia lokalna + gotowość do Restore" : "Pełny odczyt historii działa offline"}>
      <p>{connected ? "Możesz czytać backupy i od razu przygotować bezpieczny Restore na aktualnym stanie Panoramy." : "Wyszukiwanie, oś czasu, podgląd i pobieranie backupów nie wymagają hosta, loginu ani hasła. Połączenie będzie potrzebne dopiero do porównania live i wykonania Restore."}</p>
      {storage && <code className="history-storage-path">{storage}</code>}
    </Callout>
    {issues.length > 0 && <Callout severity="warning" title={`${issues.length} sesji wymaga kontroli integralności`}><p>Uszkodzona sesja nie ukrywa pozostałej historii.</p><ul>{issues.slice(0, 5).map((issue) => <li key={issue.sessionId}><code>{issue.sessionId}</code> — {issue.message}</li>)}</ul></Callout>}
    {error && <Callout severity="danger" title="Operacja historii nie powiodła się"><p>{error}</p></Callout>}

    <div className="history-layout">
      <Card className="history-list-card">
        <div className="history-toolbar">
          <div className="table-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="IP, polityka, obiekt, grupa, XPath, sesja…" /></div>
          <div className="segmented-control"><button className={kind === "all" ? "is-active" : ""} onClick={() => setKind("all")}>Wszystkie</button><button className={kind === "cleanup" ? "is-active" : ""} onClick={() => setKind("cleanup")}>Cleanup</button><button className={kind === "restore" ? "is-active" : ""} onClick={() => setKind("restore")}>Restore</button></div>
        </div>
        <div className="history-match-summary"><Database size={14} /><span>{filtered.length} sesji · {totalMatches} {tokens.length ? "pasujących operacji" : "zapisanych operacji"}</span></div>
        {!filtered.length ? <EmptyState icon={<History size={27} />} title="Brak trafień w lokalnej historii" description="Sprawdź nazwę lub usuń część filtrów. Przeszukiwane są również wartości wewnątrz backupów XML." /> : <div className="session-list">{filtered.map((session) => {
          const matches = tokens.length ? (session.historyItems ?? []).filter((item) => itemMatches(item, tokens)).length : (session.historyItems?.length ?? session.mutationCount ?? 0);
          return <button key={session.id} className={active?.id === session.id ? "is-selected" : ""} onClick={() => onSelect(session)}>
            <span className={`session-kind session-kind--${session.kind}`}>{session.kind === "restore" ? <RotateCcw size={18} /> : <FileArchive size={18} />}</span>
            <span className="session-list__copy"><span><strong>{session.description}</strong><StatusPill tone={sessionTone[session.state] ?? "neutral"}>{session.state}</StatusPill>{latestRestorable === session.id && <StatusPill tone="success">ostatnia do Restore</StatusPill>}</span><small>{formatDate(session.updatedAt)} · {session.operator} · {session.executionSource ?? "GUI"}</small><code>{shortId(session.id)} · {matches} operacji</code></span>
            <ChevronRight size={17} />
          </button>;
        })}</div>}
      </Card>

      <Card className="session-detail-card">
        {!active ? <EmptyState icon={<Activity size={27} />} title="Wybierz sesję" description="Wyniki są odczytywane z trwałego katalogu użytkownika." /> : <>
          <div className="session-detail__head"><div><span className={`session-kind session-kind--${active.kind}`}>{active.kind === "restore" ? <RotateCcw size={20} /> : <FileArchive size={20} />}</span><div><span className="eyebrow">{active.kind} · {active.executionSource ?? "GUI"} · indeks integralny</span><h2>{active.description}</h2></div></div><StatusPill tone={sessionTone[active.state] ?? "neutral"}>{active.state}</StatusPill></div>
          <dl className="session-meta"><div><dt>Session ID</dt><dd><code>{active.id}</code></dd></div><div><dt>Panorama zapisana w sesji</dt><dd>{active.panoramaHost}</dd></div><div><dt>Operator</dt><dd>{active.operator}</dd></div><div><dt>Ostatnia zmiana</dt><dd>{exactDate(active.updatedAt)}</dd></div><div><dt>Cele wejściowe</dt><dd>{active.itemCount}</dd></div><div><dt>Mutacje / backupy</dt><dd>{active.historyItems?.length ?? 0} / {active.backupCount ?? 0}</dd></div></dl>

          <div className="session-actions"><Button variant="primary" icon={<FileArchive size={16} />} loading={busy} onClick={() => onDownloadBundle(active)}>Pobierz pełny backup ZIP</Button>{active.canReconcileExternal && <Button icon={<SquareTerminal size={16} />} disabled={busy || !connected} onClick={() => setConfirmReconcile(true)}>{connected ? "Zweryfikuj wykonanie CLI/API" : "Połącz, aby zweryfikować CLI/API"}</Button>}</div>
          <div className="persistent-backup-note"><ShieldCheck size={17} /><span><strong>Historia i backup nie znikają po zamknięciu.</strong><small>{storage ? `${storage}\\${active.id}` : active.id}</small></span></div>

          <div className="history-handmode-panel">
            <header><SquareTerminal size={18} /><span><strong>Hand Mode z tej sesji</strong><small>Prawdziwe PAN-OS CLI z zapisanego PatchSetu · działa offline</small></span>{activeHandMode ? <StatusPill tone={activeHandMode.sizeBytes === 0 && (active.mutationCount ?? 0) > 0 ? "danger" : "success"}>{activeHandMode.sizeBytes === 0 && (active.mutationCount ?? 0) > 0 ? "BLOCK" : "READY"}</StatusPill> : <StatusPill tone="warning">STARA SESJA</StatusPill>}</header>
            {copyError && <Callout severity="danger" title="Nie udało się skopiować"><p>{copyError}</p></Callout>}
            {!activeHandMode ? <div className="history-handmode-missing"><p>Ta sesja powstała przed dodaniem nowego renderera. Toolbox może dopisać nowe pliki CLI lokalnie, nie ruszając starego <code>commands.txt</code>, backupów ani Panoramy.</p><Button variant="primary" icon={<SquareTerminal size={15} />} loading={busy} onClick={() => onMaterializeHandMode(active)}>Wygeneruj Hand Mode offline</Button></div> : <div className="history-handmode-actions">
              <Button icon={<FileText size={14} />} onClick={() => void openArtifact(active.id, activeHandMode.file)}>Wyświetl komendy</Button>
              <Button variant="primary" icon={<ClipboardCopy size={14} />} disabled={activeHandMode.sizeBytes === 0 && (active.mutationCount ?? 0) > 0} onClick={() => void copyArtifact(active.id, activeHandMode.file)}>{copiedArtifact === `${active.id}:${activeHandMode.file}` ? "Skopiowano" : "Kopiuj wszystkie"}</Button>
              <Button icon={<Download size={14} />} onClick={() => onDownloadArtifact(active.id, activeHandMode.file)}>Pobierz TXT</Button>
              {activeRollback && <Button variant="ghost" icon={<RotateCcw size={14} />} onClick={() => void openArtifact(active.id, activeRollback.file)}>Rollback</Button>}
              {activeInstructions && <Button variant="ghost" onClick={() => void openArtifact(active.id, activeInstructions.file)}>Instrukcja</Button>}
            </div>}
            {riskyHandMode.map((artifact) => <div className="history-handmode-risky" key={artifact.file}><AlertOctagon size={18} /><span><strong>{artifact.kind.includes("conflict") ? "Konfliktowy Restore" : "Elementy wykluczone z planu"}</strong><small>Osobny zestaw poza aktywnym PatchSetem. Wymaga jawnego review; nie łącz go automatycznie z bezpiecznymi komendami.</small></span><div><Button variant="danger" onClick={() => void openArtifact(active.id, artifact.file)}>Wyświetl</Button><Button variant="danger" disabled={artifact.sizeBytes === 0} onClick={() => setConfirmRiskyCopy({ sessionId: active.id, file: artifact.file })}>Kopiuj…</Button><Button onClick={() => onDownloadArtifact(active.id, artifact.file)}>Pobierz</Button></div></div>)}
          </div>

          {active.kind === "cleanup" && <div className="detail-section"><h3><RotateCcw size={17} /> Przywracanie według celu wejściowego</h3>{(active.targets ?? []).length ? <div className="restore-target-list">{(active.targets ?? []).map((target) => <label key={target}><input type="checkbox" checked={selectedTargets.has(target)} onChange={() => toggleTarget(target)} disabled={!active.canRestore} /><span><strong>{target.replace(/^(object|group|policy):/, "")}</strong><small>{target.includes(":") ? target.split(":", 1)[0] : "IP"}</small></span><b>{(active.backupItems ?? []).filter((item) => item.targets.includes(target)).length} plików</b></label>)}</div> : <p className="muted-value">Sesja nie zawiera celów wejściowych.</p>}<div className="restore-actions"><Button disabled={!active.canRestore || selectedTargets.size === 0} onClick={() => onRestoreTargets([...selectedTargets])}>Restore zaznaczonych ({selectedTargets.size})</Button><Button variant="primary" disabled={!active.canRestore} onClick={() => onRestore(active)}>Restore całej sesji</Button></div>{!active.canRestore && active.canReconcileExternal && <Callout severity="info" title="Brak dowodu wykonania"><p>Plan lub komendy nie oznaczają zmiany w Panoramie. Dopiero live reconciliation może oznaczyć tę sesję jako wykonaną i odblokować Restore.</p></Callout>}</div>}

          <div className="detail-section history-mutations"><h3><Search size={17} /> {tokens.length ? `Trafienia dla „${query.trim()}”` : "Operacje zapisane w sesji"} ({activeItems.length})</h3>{activeItems.length ? <div className="history-mutation-list">{activeItems.map((item) => <article key={item.id} className={item.wasApplied ? "was-applied" : "was-planned"}>
            <header><div><strong>{item.entityName}</strong><small>{item.entityType} · {item.scope}{item.rulebase ? ` · ${item.rulebase}` : ""}{item.policyType ? ` / ${item.policyType}` : ""}</small></div><StatusPill tone={executionTone[item.executionStatus]}>{executionLabel[item.executionStatus]}</StatusPill></header>
            {!item.wasApplied && <p className="history-proof-note">Brak dowodu wykonania — ta mutacja pozostała wyłącznie w planie.</p>}
            <dl className="history-action-times"><div><dt>Plan</dt><dd>{exactDate(item.plannedAt)}</dd></div><div><dt>Candidate</dt><dd>{exactDate(item.appliedAt)}</dd></div><div><dt>Commit</dt><dd>{exactDate(item.committedAt)}</dd></div><div><dt>Push</dt><dd>{exactDate(item.pushedAt)}</dd></div>{item.restoredAt && <div><dt>Restore</dt><dd>{exactDate(item.restoredAt)}</dd></div>}</dl>
            <code className="history-xpath">{item.xpath}</code>
            <div className="history-target-chips">{item.targets.map((target) => <span key={target}>{target}</span>)}</div>
            <div className="history-mutation-actions">{item.backupFile && <><Button variant="ghost" icon={<FileText size={14} />} onClick={() => void openArtifact(active.id, item.backupFile!)}>Wyświetl backup</Button><Button variant="ghost" icon={<Download size={14} />} onClick={() => onDownloadArtifact(active.id, item.backupFile!)}>Pobierz</Button></>}{item.canQuickRestore && <Button variant="primary" icon={<RotateCcw size={14} />} onClick={() => onRestoreTargets(item.restoreTargets)}>{connected ? "Szybki Restore" : "Przygotuj Restore"}</Button>}</div>
            <details><summary>Operacje API i rollback ({item.operations.length})</summary><div className="history-operation-list">{item.operations.map((operation, index) => <div key={`${operation.direction}-${index}`}><StatusPill tone={operation.direction === "forward" ? "warning" : "success"}>{operation.direction === "forward" ? "wykonanie" : "rollback"}</StatusPill><code>{operation.action} {operation.xpath}</code></div>)}</div></details>
          </article>)}</div> : <p className="muted-value">Sesja pasuje po metadanych, ale żadna pojedyncza mutacja nie zawiera wszystkich szukanych wartości.</p>}</div>

          <details className="history-timeline"><summary><span><Clock3 size={16} /> Dokładna oś czasu sesji ({active.timeline?.length ?? 0})</span><ChevronRight size={16} /></summary><div>{(active.timeline ?? []).map((event) => <div key={event.sequence}><time>{exactDate(event.timestamp)}</time><span><strong>{event.label}</strong><small>{event.state ?? event.source ?? event.eventType}{event.detail ? ` · ${event.detail}` : ""}</small></span></div>)}</div></details>

          <details className="session-backup-details"><summary><span><FileArchive size={16} /> Wszystkie pliki sesji ({active.artifacts?.length ?? 0})</span><ChevronRight size={16} /></summary><div className="history-artifact-list">{(active.artifacts ?? []).map((artifact) => <div key={artifact.file}><span><strong>{artifact.file}</strong><small>{artifact.kind} · {artifact.sizeBytes == null ? "rozmiar liczony przy pobraniu" : `${artifact.sizeBytes.toLocaleString("pl-PL")} B`}</small></span><div>{artifact.viewable && <Button variant="ghost" onClick={() => void openArtifact(active.id, artifact.file)}>Wyświetl</Button>}<Button variant="ghost" onClick={() => onDownloadArtifact(active.id, artifact.file)}>Pobierz</Button></div></div>)}</div></details>
          {active.sourceSessionId && <div className="source-session"><RotateCcw size={16} /><span>Źródłowe sesje cleanup ({active.sourceSessionIds?.length || 1})</span><code>{active.sourceSessionIds?.join(", ") || active.sourceSessionId}</code></div>}
          <div className="detail-section"><h3><CloudUpload size={17} /> Joby Panorama zapisane w sesji</h3>{active.jobs.length ? active.jobs.map((job) => <div className="history-job" key={job.id}><div><StatusPill tone={job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning"}>{job.state}</StatusPill><span><strong>{job.kind.toUpperCase()} · {job.id}</strong><small>{job.message}</small></span></div><ProgressBar value={job.progress} /></div>) : <p className="muted-value">Brak jobów Panorama w tej sesji.</p>}</div>
        </>}
      </Card>
    </div>

    {confirmReconcile && active && <div className="write-confirm-backdrop"><div className="write-confirm" role="dialog" aria-modal="true"><div><AlertTriangle size={22} /><strong>Zweryfikować wykonanie komend poza Toolboxem?</strong></div><p>To nie wykona żadnej zmiany. Toolbox pobierze live running i Candidate, sprawdzi wynik każdej planowanej operacji oraz kolejność polityk. Tylko pełna zgodność odblokuje Restore.</p><div><Button onClick={() => setConfirmReconcile(false)}>Anuluj</Button><Button variant="primary" onClick={() => { setConfirmReconcile(false); onReconcileExternal(active); }}>Sprawdź i zarejestruj</Button></div></div></div>}
    {confirmRiskyCopy && <div className="write-confirm-backdrop"><div className="write-confirm write-confirm--critical" role="dialog" aria-modal="true" aria-labelledby="history-risky-handmode-title"><div><AlertOctagon size={22} /><strong id="history-risky-handmode-title">Kopiujesz komendy poza bezpiecznym planem</strong></div><p>Ten zestaw zawiera elementy wykluczone albo konfliktowy Restore. Jego wykonanie może naruszyć DEFAULT, świeżą politykę lub późniejszą zmianę operatora. Przejrzyj pełny plik i aktualny config.</p><div><Button onClick={() => setConfirmRiskyCopy(null)}>Anuluj</Button><Button variant="danger" onClick={() => { const value = confirmRiskyCopy; setConfirmRiskyCopy(null); void copyArtifact(value.sessionId, value.file); }}>Rozumiem — kopiuj</Button></div></div></div>}
    {artifactViewer && <div className="artifact-viewer-backdrop"><div className="artifact-viewer" role="dialog" aria-modal="true" aria-label={`Podgląd ${artifactViewer.file}`}><header><div><FileText size={19} /><span><strong>{artifactViewer.file}</strong><small>Odczyt lokalny · integralność wskazanego pliku sprawdzana przed wyświetleniem</small></span></div><div>{!artifactViewer.loading && !artifactViewer.error && <Button variant="ghost" icon={<ClipboardCopy size={14} />} onClick={() => riskyHandMode.some((artifact) => artifact.file === artifactViewer.file) ? setConfirmRiskyCopy({ sessionId: artifactViewer.sessionId, file: artifactViewer.file }) : void copyArtifact(artifactViewer.sessionId, artifactViewer.file)}>{copiedArtifact === `${artifactViewer.sessionId}:${artifactViewer.file}` ? "Skopiowano" : "Kopiuj"}</Button>}<Button variant="ghost" icon={<Download size={14} />} onClick={() => onDownloadArtifact(artifactViewer.sessionId, artifactViewer.file)}>Pobierz</Button><button onClick={() => setArtifactViewer(null)} aria-label="Zamknij podgląd"><X size={19} /></button></div></header>{artifactViewer.loading ? <div className="artifact-viewer-loading"><RefreshCw className="spin" size={22} /><span>Sprawdzanie i odczyt backupu…</span></div> : artifactViewer.error ? <Callout severity="danger" title="Nie można wyświetlić pliku"><p>{artifactViewer.error}</p></Callout> : <pre>{artifactViewer.content}</pre>}</div></div>}
  </div>;
}
