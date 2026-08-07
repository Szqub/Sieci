import { CheckCircle2, Clock3, LoaderCircle, ServerCog, XCircle } from "lucide-react";
import type { ExecutionJob, ExecutionProgressItem } from "../model";
import { Card, StatusPill } from "./Primitives";

const stageLabel = {
  candidate: "Candidate",
  review: "Pełny diff i scope guard",
  commit: "Commit Panorama",
  push: "Push do urządzeń",
};

function eventTitle(item: ExecutionProgressItem): string {
  return item.entityKey || item.message || item.event || "Aktualizacja operacji";
}

function eventDetail(item: ExecutionProgressItem): string {
  if (item.jobId) {
    const panorama = typeof item.panoramaProgress === "number" ? ` · Panorama ${item.panoramaProgress}%` : "";
    const polls = item.pollCount ? ` · poll ${item.pollCount}` : "";
    return `job ${item.jobId} · ${item.status || "status oczekiwany"}${panorama}${polls}`;
  }
  if (item.action) {
    const operations = item.totalOperations
      ? ` · ${item.completedOperations ?? 0}/${item.totalOperations}`
      : "";
    return `${item.action}${operations}${item.xpath ? ` · ${item.xpath}` : ""}`;
  }
  return item.details || item.event || "etap kontrolny";
}

export function ExecutionProgress({ job }: { job: ExecutionJob }) {
  const running = job.state === "queued" || job.state === "running";
  const waitingForPanorama = running && job.current?.event === "panorama-job-poll" && typeof job.current.panoramaProgress !== "number";
  const indeterminate = running && (waitingForPanorama || Boolean(job.current?.indeterminate) || ["preflight-candidate", "review-running", "review-candidate", "review-build"].includes(job.current?.event ?? ""));
  const commitNotDispatched = running && job.kind === "commit" && !job.current?.jobId;
  const elapsed = job.current?.elapsedSeconds;
  const tone = job.state === "success" ? "success" : job.state === "failed" ? "danger" : "warning";

  return (
    <Card className={`execution-progress-card ${indeterminate ? "is-indeterminate" : ""}`} aria-live="polite">
      <div className="execution-progress-head">
        <span className="execution-progress-icon">
          {job.state === "success" ? <CheckCircle2 size={20} /> : job.state === "failed" ? <XCircle size={20} /> : <ServerCog className="spin" size={20} />}
        </span>
        <div>
          <span className="eyebrow">{stageLabel[job.kind]} · live API</span>
          <strong>{job.message}</strong>
          <small>{job.current?.entityKey || job.current?.event || "Przygotowanie bezpiecznej operacji"}</small>
        </div>
        <span className="execution-progress-status">
          <StatusPill tone={tone}>{job.state}</StatusPill>
          <b>{job.progress}%</b>
        </span>
      </div>

      <div className="execution-progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={job.progress} aria-label={`Postęp ${stageLabel[job.kind]}`}>
        <span style={{ width: `${Math.max(0, Math.min(100, job.progress))}%` }} />
        {indeterminate && <i />}
      </div>

      <div className="execution-progress-meta">
        <span><Clock3 size={14} /> {typeof elapsed === "number" ? `${elapsed.toFixed(1)} s` : "pomiar wystartował"}</span>
        {job.current?.jobId && <span>Panorama job <code>{job.current.jobId}</code></span>}
        {commitNotDispatched && <span className="preflight-notice">Job nie jest jeszcze w Panoramie — trwa lokalny/live preflight</span>}
        {waitingForPanorama && <span>Panorama nie raportuje procentu — job jest aktywnie odpytywany</span>}
      </div>

      <div className="execution-operation-log" aria-label="Log etapów wykonania">
        {job.items.slice(-12).map((item, index) => {
          const terminal = item.event === "operation-ok" || item.event === "stage-finished" || item.event === "panorama-job-finished";
          const active = running && index === job.items.slice(-12).length - 1;
          return (
            <div key={`${item.sequence ?? item.mutationId ?? item.event}-${index}`}>
              {terminal ? <CheckCircle2 className="is-complete" size={14} /> : active ? <LoaderCircle className="spin" size={14} /> : <span className="log-dot" />}
              <span><strong>{eventTitle(item)}</strong><small>{eventDetail(item)}</small></span>
              <time>{typeof item.elapsedSeconds === "number" ? `${item.elapsedSeconds.toFixed(1)} s` : `${item.progress ?? 0}%`}</time>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
