import { Activity, AlertTriangle, ChevronRight, CloudUpload, FileArchive, History, RefreshCw, RotateCcw, Search, ShieldCheck, SquareTerminal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { SessionState, ToolboxSession } from "../model";
import { formatDate, shortId } from "../model";
import { Button, Callout, Card, EmptyState, PageHeader, ProgressBar, StatusPill } from "../components/Primitives";

interface HistoryPageProps {
  sessions: ToolboxSession[];
  selected: ToolboxSession | null;
  busy: boolean;
  error: string | null;
  onRefresh: () => void;
  onSelect: (session: ToolboxSession) => void;
  onRestore: (session: ToolboxSession) => void;
  onRestoreTargets: (targets: string[]) => void;
  onDownloadBundle: (session: ToolboxSession) => void;
  onReconcileExternal: (session: ToolboxSession) => void;
}

const sessionTone: Partial<Record<SessionState, "neutral" | "accent" | "success" | "warning" | "danger" | "info">> = {
  PLANNED: "info", WRITING_CANDIDATE: "warning", CANDIDATE_APPLIED: "warning", COMMITTING: "warning", COMMITTED: "accent", PUSHING: "warning", PUSHED: "success", RESTORING: "warning", RESTORED: "success", PARTIAL: "warning", FAILED: "danger", CONFLICT: "danger", OUTCOME_UNKNOWN: "danger",
};

export function HistoryPage({ sessions, selected, busy, error, onRefresh, onSelect, onRestore, onRestoreTargets, onDownloadBundle, onReconcileExternal }: HistoryPageProps) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | "cleanup" | "restore">("all");
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
  const [confirmReconcile, setConfirmReconcile] = useState(false);
  useEffect(() => { setSelectedTargets(new Set()); setConfirmReconcile(false); }, [selected?.id]);
  const filtered = useMemo(() => sessions.filter((session) => {
    if (kind !== "all" && session.kind !== kind) return false;
    const text = `${session.id} ${session.description} ${session.operator} ${session.panoramaHost} ${session.affectedDeviceGroups.join(" ")} ${(session.targets ?? []).join(" ")}`.toLowerCase();
    return text.includes(query.toLowerCase());
  }), [sessions, query, kind]);
  const latestRestorable = sessions.find((session) => session.kind === "cleanup" && session.canRestore)?.id;

  const toggleTarget = (target: string) => setSelectedTargets((current) => {
    const next = new Set(current);
    if (next.has(target)) next.delete(target); else next.add(target);
    return next;
  });

  return <div className="page-stack history-design-page">
    <PageHeader eyebrow="Operations / Backups" title="Historia, backup i Restore" description="Sesje są trwale zapisane w folderze backupy obok aplikacji. Wybierz ostatnią stabilną sesję, całość albo konkretne cele." actions={<Button onClick={onRefresh} loading={busy} icon={<RefreshCw size={16} />}>Odśwież</Button>} />
    {error && <Callout severity="danger" title="Operacja historii nie powiodła się"><p>{error}</p></Callout>}

    <div className="history-layout">
      <Card className="history-list-card">
        <div className="history-toolbar"><div className="table-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="ID, cel, DG, operator…" /></div><div className="segmented-control"><button className={kind === "all" ? "is-active" : ""} onClick={() => setKind("all")}>Wszystkie</button><button className={kind === "cleanup" ? "is-active" : ""} onClick={() => setKind("cleanup")}>Cleanup</button><button className={kind === "restore" ? "is-active" : ""} onClick={() => setKind("restore")}>Restore</button></div></div>
        {!filtered.length ? <EmptyState icon={<History size={27} />} title="Brak pasujących sesji" description="Zmień filtr albo utwórz pierwszy plan cleanup." /> : <div className="session-list">{filtered.map((session) => <button key={session.id} className={selected?.id === session.id ? "is-selected" : ""} onClick={() => onSelect(session)}><span className={`session-kind session-kind--${session.kind}`}>{session.kind === "cleanup" ? <FileArchive size={18} /> : <RotateCcw size={18} />}</span><span className="session-list__copy"><span><strong>{session.description}</strong><StatusPill tone={sessionTone[session.state] ?? "neutral"}>{session.state}</StatusPill>{latestRestorable === session.id && <StatusPill tone="success">ostatnia do Restore</StatusPill>}</span><small>{formatDate(session.updatedAt)} · {session.operator} · {session.executionSource ?? "GUI"}</small><code>{shortId(session.id)}</code></span><ChevronRight size={17} /></button>)}</div>}
      </Card>

      <Card className="session-detail-card">
        {!selected ? <EmptyState icon={<Activity size={27} />} title="Wybierz sesję" description="Domyślnie zaznaczana jest ostatnia stabilna sesja cleanup." /> : <>
          <div className="session-detail__head"><div><span className={`session-kind session-kind--${selected.kind}`}>{selected.kind === "cleanup" ? <FileArchive size={20} /> : <RotateCcw size={20} />}</span><div><span className="eyebrow">{selected.kind} · {selected.executionSource ?? "GUI"}</span><h2>{selected.description}</h2></div></div><StatusPill tone={sessionTone[selected.state] ?? "neutral"}>{selected.state}</StatusPill></div>
          <dl className="session-meta"><div><dt>Session ID</dt><dd><code>{selected.id}</code></dd></div><div><dt>Panorama</dt><dd>{selected.panoramaHost}</dd></div><div><dt>Operator</dt><dd>{selected.operator}</dd></div><div><dt>Utworzono</dt><dd>{formatDate(selected.createdAt)}</dd></div><div><dt>Cele</dt><dd>{selected.itemCount}</dd></div><div><dt>Backupy encji</dt><dd>{selected.backupCount ?? 0}</dd></div></dl>

          <div className="session-actions"><Button variant="primary" icon={<FileArchive size={16} />} loading={busy} onClick={() => onDownloadBundle(selected)}>Pobierz pełny backup ZIP</Button>{selected.canReconcileExternal && <Button icon={<SquareTerminal size={16} />} disabled={busy} onClick={() => setConfirmReconcile(true)}>Zweryfikuj wykonanie CLI/API</Button>}</div>
          <div className="persistent-backup-note"><ShieldCheck size={17} /><span><strong>Backup nie znika po zamknięciu.</strong><small>Folder portable: backupy\sessions\{selected.id}</small></span></div>

          {selected.kind === "cleanup" && <div className="detail-section"><h3><RotateCcw size={17} /> Cele możliwe do odtworzenia</h3>{(selected.targets ?? []).length ? <div className="restore-target-list">{(selected.targets ?? []).map((target) => <label key={target}><input type="checkbox" checked={selectedTargets.has(target)} onChange={() => toggleTarget(target)} disabled={!selected.canRestore} /><span><strong>{target.replace(/^(object|group|policy):/, "")}</strong><small>{target.includes(":") ? target.split(":", 1)[0] : "IP"}</small></span><b>{(selected.backupItems ?? []).filter((item) => item.targets.includes(target)).length} plików</b></label>)}</div> : <p className="muted-value">Sesja nie zawiera celów wejściowych.</p>}<div className="restore-actions"><Button disabled={!selected.canRestore || selectedTargets.size === 0} onClick={() => onRestoreTargets([...selectedTargets])}>Restore zaznaczonych ({selectedTargets.size})</Button><Button variant="primary" disabled={!selected.canRestore} onClick={() => onRestore(selected)}>Restore całej sesji</Button></div>{!selected.canRestore && selected.canReconcileExternal && <Callout severity="info" title="Plan z komendami CLI nie jest jeszcze historią wykonania"><p>Kliknij „Zweryfikuj wykonanie CLI/API”. Toolbox porówna live każdy XPath i dopiero wtedy odblokuje Restore.</p></Callout>}</div>}

          <details className="session-backup-details"><summary><span><FileArchive size={16} /> Pliki backupu per encja ({selected.backupItems?.length ?? 0})</span><ChevronRight size={16} /></summary><div>{(selected.backupItems ?? []).map((backup) => <div key={backup.mutationId}><span><strong>{backup.entityName}</strong><small>{backup.entityType} · {(backup.targets ?? []).join(", ")}</small></span><code>{backup.file}</code></div>)}</div></details>
          {selected.sourceSessionId && <div className="source-session"><RotateCcw size={16} /><span>Źródłowe sesje cleanup ({selected.sourceSessionIds?.length || 1})</span><code>{selected.sourceSessionIds?.join(", ") || selected.sourceSessionId}</code></div>}
          <div className="detail-section"><h3><CloudUpload size={17} /> Joby Panorama</h3>{selected.jobs.length ? selected.jobs.map((job) => <div className="history-job" key={job.id}><div><StatusPill tone={job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning"}>{job.state}</StatusPill><span><strong>{job.kind.toUpperCase()} · {job.id}</strong><small>{job.message}</small></span></div><ProgressBar value={job.progress} /></div>) : <p className="muted-value">Brak jobów Panorama w tej sesji.</p>}</div>
        </>}
      </Card>
    </div>

    {confirmReconcile && selected && <div className="write-confirm-backdrop"><div className="write-confirm" role="dialog" aria-modal="true"><div><AlertTriangle size={22} /><strong>Zweryfikować wykonanie komend poza Toolboxem?</strong></div><p>To nie wykona żadnej zmiany. Toolbox pobierze live running i Candidate, sprawdzi wynik każdej planowanej operacji oraz kolejność polityk. Tylko pełna zgodność odblokuje Restore.</p><div><Button onClick={() => setConfirmReconcile(false)}>Anuluj</Button><Button variant="primary" onClick={() => { setConfirmReconcile(false); onReconcileExternal(selected); }}>Sprawdź i zarejestruj</Button></div></div></div>}
  </div>;
}
