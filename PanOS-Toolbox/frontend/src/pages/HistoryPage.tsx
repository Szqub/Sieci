import { Activity, ChevronRight, Clock3, CloudUpload, FileArchive, History, RefreshCw, RotateCcw, Search } from "lucide-react";
import { useMemo, useState } from "react";
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
}

const sessionTone: Partial<Record<SessionState, "neutral" | "accent" | "success" | "warning" | "danger" | "info">> = {
  PLANNED: "info", WRITING_CANDIDATE: "warning", CANDIDATE_APPLIED: "warning", COMMITTING: "warning", COMMITTED: "accent", PUSHING: "warning", PUSHED: "success", RESTORING: "warning", RESTORED: "success", PARTIAL: "warning", FAILED: "danger", CONFLICT: "danger", OUTCOME_UNKNOWN: "danger",
};

export function HistoryPage({ sessions, selected, busy, error, onRefresh, onSelect, onRestore }: HistoryPageProps) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | "cleanup" | "restore">("all");
  const filtered = useMemo(() => sessions.filter((session) => {
    if (kind !== "all" && session.kind !== kind) return false;
    const text = `${session.id} ${session.description} ${session.operator} ${session.panoramaHost} ${session.affectedDeviceGroups.join(" ")}`.toLowerCase();
    return text.includes(query.toLowerCase());
  }), [sessions, query, kind]);

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Operations / History" title="Historia sesji i jobów" description="Każdy plan, write, commit, push i restore pozostawia trwały manifest, backup oraz dziennik odpowiedzi API." actions={<Button onClick={onRefresh} loading={busy} icon={<RefreshCw size={16} />}>Odśwież</Button>} />
      {error && <Callout severity="danger" title="Nie udało się odczytać historii"><p>{error}</p></Callout>}

      <div className="history-layout">
        <Card className="history-list-card">
          <div className="history-toolbar">
            <div className="table-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="ID, adres, DG, operator…" /></div>
            <div className="segmented-control"><button className={kind === "all" ? "is-active" : ""} onClick={() => setKind("all")}>Wszystkie</button><button className={kind === "cleanup" ? "is-active" : ""} onClick={() => setKind("cleanup")}>Cleanup</button><button className={kind === "restore" ? "is-active" : ""} onClick={() => setKind("restore")}>Restore</button></div>
          </div>
          {!filtered.length ? <EmptyState icon={<History size={27} />} title="Brak pasujących sesji" description="Zmień filtr albo utwórz pierwszy plan cleanup." /> : <div className="session-list">
            {filtered.map((session) => <button key={session.id} className={selected?.id === session.id ? "is-selected" : ""} onClick={() => onSelect(session)}>
              <span className={`session-kind session-kind--${session.kind}`}>{session.kind === "cleanup" ? <FileArchive size={18} /> : <RotateCcw size={18} />}</span>
              <span className="session-list__copy"><span><strong>{session.description}</strong><StatusPill tone={sessionTone[session.state] ?? "neutral"}>{session.state}</StatusPill></span><small>{formatDate(session.updatedAt)} · {session.operator}</small><code>{shortId(session.id)}</code></span>
              <ChevronRight size={17} />
            </button>)}
          </div>}
        </Card>

        <Card className="session-detail-card">
          {!selected ? <EmptyState icon={<Activity size={27} />} title="Wybierz sesję" description="Zobaczysz dokładny stan, zakres, joby i dostępne artefakty." /> : <>
            <div className="session-detail__head"><div><span className={`session-kind session-kind--${selected.kind}`}>{selected.kind === "cleanup" ? <FileArchive size={20} /> : <RotateCcw size={20} />}</span><div><span className="eyebrow">{selected.kind} session</span><h2>{selected.description}</h2></div></div><StatusPill tone={sessionTone[selected.state] ?? "neutral"}>{selected.state}</StatusPill></div>
            <dl className="session-meta"><div><dt>Session ID</dt><dd><code>{selected.id}</code></dd></div><div><dt>Panorama</dt><dd>{selected.panoramaHost}</dd></div><div><dt>Operator</dt><dd>{selected.operator}</dd></div><div><dt>Utworzono</dt><dd>{formatDate(selected.createdAt)}</dd></div><div><dt>Elementy</dt><dd>{selected.itemCount}</dd></div><div><dt>Device groups</dt><dd>{selected.affectedDeviceGroups.join(", ")}</dd></div></dl>
            {selected.sourceSessionId && <div className="source-session"><RotateCcw size={16} /><span>Źródłowe sesje cleanup ({selected.sourceSessionIds?.length || 1})</span><code>{selected.sourceSessionIds?.join(", ") || selected.sourceSessionId}</code></div>}
            <div className="detail-section"><h3><CloudUpload size={17} /> Joby Panorama</h3>{selected.jobs.length ? selected.jobs.map((job) => <div className="history-job" key={job.id}><div><StatusPill tone={job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning"}>{job.state}</StatusPill><span><strong>{job.kind.toUpperCase()} · {job.id}</strong><small>{job.message}</small></span></div><ProgressBar value={job.progress} /></div>) : <p className="muted-value">Ta sesja nie uruchomiła jeszcze jobów.</p>}</div>
            <div className="detail-section"><h3><Clock3 size={17} /> Artefakty sesji</h3><div className="artifact-grid"><button><FileArchive size={17} /><span><strong>manifest.json</strong><small>integralność i operacje</small></span></button><button><FileArchive size={17} /><span><strong>pre_running.xml</strong><small>awaryjny snapshot</small></span></button><button><FileArchive size={17} /><span><strong>report.txt</strong><small>raport administratora</small></span></button></div></div>
            {selected.kind === "cleanup" && <Button variant="primary" icon={<RotateCcw size={17} />} onClick={() => onRestore(selected)}>Przygotuj Emergency Restore</Button>}
          </>}
        </Card>
      </div>
    </div>
  );
}
