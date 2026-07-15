import { useEffect, useState } from "react";
import { api, ToolboxApiError } from "./api/client";
import { Shell, type ViewId } from "./components/Shell";
import type {
  AuditResult,
  CleanupPlan,
  ConnectionDraft,
  ConnectionSession,
  DoctorResult,
  RestorePlan,
  ToolboxSession,
} from "./model";
import { parseAddressInput } from "./utils";
import { AuditPage } from "./pages/AuditPage";
import { CleanupPage } from "./pages/CleanupPage";
import { ConnectionPage } from "./pages/ConnectionPage";
import { HistoryPage } from "./pages/HistoryPage";
import { PlanPage } from "./pages/PlanPage";
import { RestorePage } from "./pages/RestorePage";

const initialConnection: ConnectionDraft = {
  host: "",
  username: "",
  password: "",
  ssl: true,
  verifySsl: true,
  apiMaxStage: "read-only",
};

type MainBusy = "connect" | "doctor" | "analyze" | "audit" | "history" | null;
type StageBusy = "candidate" | "commit" | "push" | "download" | null;
type RestoreBusy = "plan" | "candidate" | "commit" | "push" | "download" | null;
type DemoModule = typeof import("./demo");

function getErrorMessage(error: unknown): string {
  if (error instanceof ToolboxApiError) {
    const parts = [error.message, error.detail, error.correlationId ? `ID: ${error.correlationId}` : undefined];
    return parts.filter(Boolean).join(" · ");
  }
  if (error instanceof Error) return error.message;
  return "Nieznany błąd operacji.";
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [view, setView] = useState<ViewId>("connection");
  const [theme, setTheme] = useState<"light" | "dark">(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const [draft, setDraft] = useState<ConnectionDraft>(initialConnection);
  const [connection, setConnection] = useState<ConnectionSession | null>(null);
  const [doctor, setDoctor] = useState<DoctorResult | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [demoApi, setDemoApi] = useState<DemoModule | null>(null);
  const [writeEnabled, setWriteEnabled] = useState(false);
  const [mainBusy, setMainBusy] = useState<MainBusy>(null);
  const [stageBusy, setStageBusy] = useState<StageBusy>(null);
  const [restoreBusy, setRestoreBusy] = useState<RestoreBusy>(null);
  const [error, setError] = useState<string | null>(null);

  const [addressText, setAddressText] = useState("");
  const [runIcmp, setRunIcmp] = useState(true);
  const [recentHitDays, setRecentHitDays] = useState(14);
  const [cleanupPlan, setCleanupPlan] = useState<CleanupPlan | null>(null);
  const [executionSession, setExecutionSession] = useState<ToolboxSession | null>(null);

  const [auditQuery, setAuditQuery] = useState("");
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [sessions, setSessions] = useState<ToolboxSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<ToolboxSession | null>(null);

  const [restoreQuery, setRestoreQuery] = useState("");
  const [restorePlan, setRestorePlan] = useState<RestorePlan | null>(null);
  const [restoreSession, setRestoreSession] = useState<ToolboxSession | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    if (view === "history" && connection && sessions.length === 0) void refreshHistory();
    // refreshHistory is intentionally event-like; connection/view are the triggers.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, connection]);

  const navigate = (next: ViewId) => {
    setError(null);
    setView(next);
  };

  const connect = async () => {
    setMainBusy("connect");
    setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoConnection(draft) : await api.connect(draft);
      setConnection(result);
      setDraft((current) => ({ ...current, password: "" }));
      setWriteEnabled(false);
      setView("cleanup");
    } catch (connectError) {
      setError(getErrorMessage(connectError));
    } finally {
      setMainBusy(null);
    }
  };

  const runDoctor = async () => {
    setMainBusy("doctor");
    setError(null);
    try {
      setDoctor(demoMode && demoApi ? demoApi.demoDoctor : await api.doctor(draft));
    } catch (doctorError) {
      setError(getErrorMessage(doctorError));
    } finally {
      setMainBusy(null);
    }
  };

  const enableDemo = async () => {
    if (!import.meta.env.DEV) return;
    const demo = await import("./demo");
    const demoDraft: ConnectionDraft = {
      host: draft.host || "panorama.lab.local",
      username: draft.username || "superadmin",
      password: "",
      ssl: true,
      verifySsl: false,
      apiMaxStage: "push",
    };
    setDemoApi(demo);
    setDemoMode(true);
    setDraft(demoDraft);
    setConnection(demo.demoConnection(demoDraft));
    setDoctor(demo.demoDoctor);
    setSessions(demo.demoSessions);
    setAddressText("10.42.16.19\n10.42.16.20\n10.42.16.21\n10.42.16.22\n10.42.16.23\n10.42.16.99");
    setView("cleanup");
    setError(null);
  };

  const disconnect = async () => {
    if (!demoMode) {
      try { await api.disconnect(); } catch { /* Session is cleared locally even when server teardown fails. */ }
    }
    setConnection(null);
    setWriteEnabled(false);
    setDemoMode(false);
    setDemoApi(null);
    setExecutionSession(null);
    setRestoreSession(null);
    setView("connection");
  };

  const analyze = async () => {
    if (!connection) return;
    setMainBusy("analyze");
    setError(null);
    try {
      const addresses = parseAddressInput(addressText).addresses;
      const plan = demoMode && demoApi ? demoApi.demoCleanupPlan : await api.createCleanupPlan({ connectionId: connection.id, addresses, runIcmp, recentHitDays });
      setCleanupPlan(plan);
      setExecutionSession(null);
      setView("plan");
    } catch (analysisError) {
      setError(getErrorMessage(analysisError));
    } finally {
      setMainBusy(null);
    }
  };

  const applyCandidate = async () => {
    if (!cleanupPlan) return;
    setStageBusy("candidate"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAction(cleanupPlan.sessionId, "CANDIDATE_APPLIED", "candidate") : await api.applyCandidate(cleanupPlan.sessionId, { enableApiWrite: writeEnabled });
      setExecutionSession(result.session);
    } catch (actionError) { setError(getErrorMessage(actionError)); } finally { setStageBusy(null); }
  };

  const commitCleanup = async (allowUnisolated: boolean, allowFull: boolean) => {
    if (!cleanupPlan) return;
    const sessionId = executionSession?.id ?? cleanupPlan.sessionId;
    setStageBusy("commit"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAction(sessionId, "COMMITTED", "commit") : await api.commit(sessionId, { enableApiWrite: writeEnabled, allowUnisolatedCommit: allowUnisolated, allowFullCommit: allowFull });
      setExecutionSession(result.session);
    } catch (actionError) { setError(getErrorMessage(actionError)); } finally { setStageBusy(null); }
  };

  const pushCleanup = async () => {
    if (!cleanupPlan) return;
    const sessionId = executionSession?.id ?? cleanupPlan.sessionId;
    setStageBusy("push"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAction(sessionId, "PUSHED", "push") : await api.push(sessionId, cleanupPlan.affectedDeviceGroups, { enableApiWrite: writeEnabled });
      setExecutionSession(result.session);
    } catch (actionError) { setError(getErrorMessage(actionError)); } finally { setStageBusy(null); }
  };

  const downloadCleanup = async (artifact: "commands" | "report" | "manifest") => {
    if (!cleanupPlan) return;
    setStageBusy("download"); setError(null);
    try {
      const blob = demoMode && demoApi
        ? new Blob([artifact === "commands" ? demoApi.demoCleanupPlan.operations.map((operation) => `${operation.action} ${operation.xpath}`).join("\n") : JSON.stringify(demoApi.demoCleanupPlan, null, 2)], { type: "text/plain" })
        : await api.downloadSessionArtifact(cleanupPlan.sessionId, artifact);
      saveBlob(blob, `${cleanupPlan.sessionId}_${artifact}.${artifact === "manifest" ? "json" : "txt"}`);
    } catch (downloadError) { setError(getErrorMessage(downloadError)); } finally { setStageBusy(null); }
  };

  const runAudit = async () => {
    if (!connection) return;
    setMainBusy("audit"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAudit : await api.audit(connection.id, parseAddressInput(auditQuery).addresses);
      setAuditResult(result);
    } catch (auditError) { setError(getErrorMessage(auditError)); } finally { setMainBusy(null); }
  };

  async function refreshHistory() {
    setMainBusy("history"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoSessions : await api.listSessions();
      setSessions(result);
      if (selectedSession) setSelectedSession(result.find((session) => session.id === selectedSession.id) ?? null);
    } catch (historyError) { setError(getErrorMessage(historyError)); } finally { setMainBusy(null); }
  }

  const openRestoreForSession = (session: ToolboxSession) => {
    setRestoreQuery(session.id);
    setRestorePlan(null);
    setRestoreSession(null);
    navigate("restore");
  };

  const createRestorePlan = async (mode: "ip" | "session") => {
    if (!connection) return;
    setRestoreBusy("plan"); setError(null);
    try {
      const plan = demoMode && demoApi ? demoApi.demoRestorePlan : await api.createRestorePlan({ connectionId: connection.id, ip: mode === "ip" ? restoreQuery : undefined, sourceSessionId: mode === "session" ? restoreQuery : undefined });
      setRestorePlan(plan);
      setRestoreSession(null);
    } catch (planError) { setError(getErrorMessage(planError)); } finally { setRestoreBusy(null); }
  };

  const applyRestoreCandidate = async () => {
    if (!restorePlan) return;
    setRestoreBusy("candidate"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAction(restorePlan.sessionId, "RESTORED", "restore") : await api.applyRestoreCandidate(restorePlan.id, { enableApiWrite: writeEnabled });
      setRestoreSession(result.session);
    } catch (restoreError) { setError(getErrorMessage(restoreError)); } finally { setRestoreBusy(null); }
  };

  const commitRestore = async (allowUnisolated: boolean, allowFull: boolean) => {
    if (!restorePlan) return;
    const sessionId = restoreSession?.id ?? restorePlan.sessionId;
    setRestoreBusy("commit"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAction(sessionId, "COMMITTED", "commit") : await api.commit(sessionId, { enableApiWrite: writeEnabled, allowUnisolatedCommit: allowUnisolated, allowFullCommit: allowFull });
      setRestoreSession(result.session);
    } catch (restoreError) { setError(getErrorMessage(restoreError)); } finally { setRestoreBusy(null); }
  };

  const pushRestore = async () => {
    if (!restorePlan) return;
    const sessionId = restoreSession?.id ?? restorePlan.sessionId;
    const groups = restorePlan.affectedDeviceGroups;
    setRestoreBusy("push"); setError(null);
    try {
      const result = demoMode && demoApi ? demoApi.demoAction(sessionId, "PUSHED", "push") : await api.push(sessionId, groups, { enableApiWrite: writeEnabled });
      setRestoreSession(result.session);
    } catch (restoreError) { setError(getErrorMessage(restoreError)); } finally { setRestoreBusy(null); }
  };

  const downloadConflicts = async () => {
    if (!restorePlan) return;
    setRestoreBusy("download"); setError(null);
    try {
      const blob = demoMode && demoApi ? new Blob([JSON.stringify(restorePlan.entities.filter((entity) => entity.outcome === "conflict"), null, 2)], { type: "application/json" }) : await api.downloadSessionArtifact(restorePlan.sessionId, "conflicts");
      saveBlob(blob, `${restorePlan.sessionId}_conflicts.json`);
    } catch (downloadError) { setError(getErrorMessage(downloadError)); } finally { setRestoreBusy(null); }
  };

  let page;
  if (view === "connection") page = <ConnectionPage draft={draft} onDraftChange={setDraft} connection={connection} doctor={doctor} busy={mainBusy === "connect" || mainBusy === "doctor" ? mainBusy : null} error={error} onConnect={() => void connect()} onDoctor={() => void runDoctor()} onDemo={enableDemo} demoAvailable={import.meta.env.DEV} />;
  else if (view === "cleanup") page = <CleanupPage connection={connection} addressText={addressText} onAddressTextChange={setAddressText} runIcmp={runIcmp} onRunIcmpChange={setRunIcmp} recentHitDays={recentHitDays} onRecentHitDaysChange={setRecentHitDays} busy={mainBusy === "analyze"} error={error} onAnalyze={() => void analyze()} onOpenConnection={() => navigate("connection")} />;
  else if (view === "plan") page = <PlanPage plan={cleanupPlan} executionSession={executionSession} apiMaxStage={connection?.apiMaxStage ?? "read-only"} writeEnabled={writeEnabled} busy={stageBusy} error={error} onOpenCleanup={() => navigate("cleanup")} onApplyCandidate={() => void applyCandidate()} onCommit={(unisolated, full) => void commitCleanup(unisolated, full)} onPush={() => void pushCleanup()} onDownload={(artifact) => void downloadCleanup(artifact)} />;
  else if (view === "audit") page = <AuditPage connection={connection} query={auditQuery} onQueryChange={setAuditQuery} result={auditResult} busy={mainBusy === "audit"} error={error} onAudit={() => void runAudit()} onOpenConnection={() => navigate("connection")} />;
  else if (view === "history") page = <HistoryPage sessions={sessions} selected={selectedSession} busy={mainBusy === "history"} error={error} onRefresh={() => void refreshHistory()} onSelect={setSelectedSession} onRestore={openRestoreForSession} />;
  else page = <RestorePage query={restoreQuery} onQueryChange={setRestoreQuery} plan={restorePlan} executionSession={restoreSession} apiMaxStage={connection?.apiMaxStage ?? "read-only"} writeEnabled={writeEnabled} connected={Boolean(connection)} busy={restoreBusy} error={error} onCreatePlan={(mode) => void createRestorePlan(mode)} onApplyCandidate={() => void applyRestoreCandidate()} onCommit={(unisolated, full) => void commitRestore(unisolated, full)} onPush={() => void pushRestore()} onDownloadConflicts={() => void downloadConflicts()} onOpenConnection={() => navigate("connection")} />;

  return (
    <Shell activeView={view} onViewChange={navigate} connection={connection} writeEnabled={writeEnabled} onWriteEnabledChange={setWriteEnabled} theme={theme} onThemeChange={() => setTheme((current) => current === "dark" ? "light" : "dark")} onDisconnect={() => void disconnect()} demoMode={demoMode}>
      {page}
    </Shell>
  );
}
