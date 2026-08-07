import { useEffect, useMemo, useState } from "react";
import { api, ToolboxApiError } from "./api/client";
import { Shell, type ViewId } from "./components/Shell";
import type {
  AddressAnalysis,
  AdGroupGenerationResult,
  AnalysisJob,
  AuditResult,
  CleanupPlan,
  ConnectionDraft,
  ConnectionSession,
  DoctorResult,
  LookupEntity,
  LookupKind,
  LookupResult,
  EntityDependency,
  ExecutionJob,
  RestorePlan,
  SavedProfile,
  ToolboxNotice,
  ToolboxSession,
} from "./model";
import { parseAddressInput, parseNameInput } from "./utils";
import { AuditPage } from "./pages/AuditPage";
import { AdGroupsPage, type AdGroupDraft } from "./pages/AdGroupsPage";
import { CleanupPage } from "./pages/CleanupPage";
import { ConnectionPage } from "./pages/ConnectionPage";
import { HistoryPage } from "./pages/HistoryPage";
import { PlanPage } from "./pages/PlanPage";
import { PolicyRequestsPage } from "./pages/PolicyRequestsPage";
import { RestorePage } from "./pages/RestorePage";
import { WarningsPage } from "./pages/WarningsPage";

const initialConnection: ConnectionDraft = {
  host: "",
  username: "",
  password: "",
  ssl: true,
  verifySsl: false,
  apiMaxStage: "push",
  rememberProfile: false,
};

const initialAdGroupDraft: AdGroupDraft = {
  groupsText: "",
  outputName: "",
  mappingName: "LDAP_GM1",
  vsys: "vsys1",
  templateName: "",
};

type MainBusy = "connect" | "doctor" | "analyze" | "ad-groups" | "policy-request" | "audit" | "history" | null;
type StageBusy = "candidate" | "commit" | "push" | "download" | null;
type RestoreBusy = "plan" | "candidate" | "commit" | "push" | "download" | null;
type DemoModule = typeof import("./demo");

const wait = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

async function waitForExecutionJob(initial: ExecutionJob, onUpdate: (job: ExecutionJob) => void): Promise<ExecutionJob & { session: ToolboxSession }> {
  let job = initial;
  onUpdate(job);
  while (job.state === "queued" || job.state === "running") {
    await wait(350);
    job = await api.getExecutionJob(job.id);
    onUpdate(job);
  }
  if (job.state === "failed") throw new Error(job.error?.message || `Etap ${job.kind} został zatrzymany.`);
  if (!job.session) throw new Error(`Etap ${job.kind} nie zwrócił końcowego stanu sesji.`);
  return job as ExecutionJob & { session: ToolboxSession };
}

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
  const [analysisJob, setAnalysisJob] = useState<AnalysisJob | null>(null);
  const [executionJob, setExecutionJob] = useState<ExecutionJob | null>(null);
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [lookupBusy, setLookupBusy] = useState(false);
  const [singlePlanBusy, setSinglePlanBusy] = useState<string | null>(null);
  const [draft, setDraft] = useState<ConnectionDraft>(initialConnection);
  const [savedProfiles, setSavedProfiles] = useState<SavedProfile[]>([]);
  const [profileStorage, setProfileStorage] = useState("");
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
  const [objectText, setObjectText] = useState("");
  const [groupText, setGroupText] = useState("");
  const [policyText, setPolicyText] = useState("");
  const [runIcmp, setRunIcmp] = useState(true);
  const [recentHitDays, setRecentHitDays] = useState(14);
  const [allowDefaultPolicyOverride, setAllowDefaultPolicyOverride] = useState(false);
  const [cleanupPlan, setCleanupPlan] = useState<CleanupPlan | null>(null);
  const [executionSession, setExecutionSession] = useState<ToolboxSession | null>(null);

  const [adGroupDraft, setAdGroupDraft] = useState<AdGroupDraft>(initialAdGroupDraft);
  const [adGroupResult, setAdGroupResult] = useState<AdGroupGenerationResult | null>(null);
  const [policyRequestPlan, setPolicyRequestPlan] = useState<CleanupPlan | null>(null);

  const [auditQuery, setAuditQuery] = useState("");
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [sessions, setSessions] = useState<ToolboxSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<ToolboxSession | null>(null);

  const [restoreQuery, setRestoreQuery] = useState("");
  const [restorePlan, setRestorePlan] = useState<RestorePlan | null>(null);
  const [restoreSession, setRestoreSession] = useState<ToolboxSession | null>(null);
  const [restoreExecutionJob, setRestoreExecutionJob] = useState<ExecutionJob | null>(null);

  const notices = useMemo<ToolboxNotice[]>(() => {
    const collected: ToolboxNotice[] = [];
    const seen = new Set<string>();
    const add = (source: string, title: string, detail?: string, severity: ToolboxNotice["severity"] = "warning", context?: string) => {
      if (!detail?.trim()) return;
      const key = `${source}|${detail.trim()}`;
      if (seen.has(key)) return;
      seen.add(key);
      collected.push({ id: `notice-${collected.length + 1}`, source, title, detail: detail.trim(), severity, context });
    };

    add("Połączenie", "Ograniczenie profilu", connection?.capabilityWarning);
    lookupResult?.warnings.forEach((warning) => add("Lookup punktowy", "Informacja z wyszukiwania", warning));
    lookupResult?.found.forEach((entity) => add("Lookup punktowy", `${entity.name} jest read-only`, entity.blockedReason, "warning", `${entity.scope} · ${entity.policyType ?? entity.type}`));
    cleanupPlan?.warnings.forEach((warning) => add("Plan cleanup", warning.includes("Application Override") ? "Application Override — read-only" : "Informacja z analizy", warning));
    cleanupPlan?.addresses.forEach((target) => target.entities?.forEach((entity) => add("Plan cleanup", `${entity.name} nie zostanie wykonany automatycznie`, entity.blockedReason, "warning", `${entity.scope} · ${entity.rulebase ?? entity.type}`)));
    policyRequestPlan?.warnings.forEach((warning) => add("Nowe polityki", "Informacja z parsera / planu", warning));
    restorePlan?.warnings.forEach((warning) => add("Emergency Restore", "Konflikt bieżącego stanu", warning, "danger"));
    restorePlan?.entities.filter((entity) => entity.outcome === "conflict").forEach((entity) => add("Emergency Restore", `Konflikt: ${entity.name}`, entity.detail, "danger", `${entity.type} · ${entity.scope}`));
    adGroupResult?.warnings.forEach((warning) => add("Grupy AD", "Walidacja grup AD", warning));
    adGroupResult?.groups.filter((group) => group.status !== "valid").forEach((group) => add("Grupy AD", `${group.name}: ${group.status}`, group.detail, group.status === "error" ? "danger" : "warning"));
    if (auditResult?.residualReferenceCount) add("Audit", "Pozostały referencje", `Audit wykrył ${auditResult.residualReferenceCount} referencji wymagających przeglądu.`, "warning");
    return collected;
  }, [connection, lookupResult, cleanupPlan, policyRequestPlan, restorePlan, adGroupResult, auditResult]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    if (demoMode) return;
    void api.listProfiles().then((result) => {
      setSavedProfiles(result.profiles);
      setProfileStorage(result.storage);
    }).catch(() => {
      // Profile storage is optional for first start; connection remains usable.
    });
  }, [demoMode]);

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
      if (result.profileSaved || result.profileId) {
        const refreshed = await api.listProfiles().catch(() => null);
        if (refreshed) {
          setSavedProfiles(refreshed.profiles);
          setProfileStorage(refreshed.storage);
        }
      }
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
    setObjectText("OLD-WEB-SERVER");
    setGroupText("GRP-LEGACY-SERVERS");
    setPolicyText("ALLOW-LEGACY-APP");
    setView("cleanup");
    setError(null);
  };

  const disconnect = async () => {
    if (!demoMode) {
      try { await api.disconnect(); } catch { /* Session is cleared locally even when server teardown fails. */ }
    }
    setConnection(null);
    setWriteEnabled(false);
    setAnalysisJob(null);
    setExecutionJob(null);
    setRestoreExecutionJob(null);
    setLookupResult(null);
    setPolicyRequestPlan(null);
    setDemoMode(false);
    setDemoApi(null);
    setExecutionSession(null);
    setRestoreSession(null);
    setView("connection");
  };

  const selectSavedProfile = (profileId: string) => {
    if (!profileId) {
      setDraft((current) => ({ ...current, profileId: undefined, profileName: "", password: "", rememberProfile: false }));
      return;
    }
    const profile = savedProfiles.find((item) => item.id === profileId);
    if (!profile) return;
    setDraft({
      host: profile.host,
      username: profile.username,
      password: "",
      ssl: profile.ssl,
      verifySsl: profile.verifySsl,
      apiMaxStage: profile.apiMaxStage,
      profileId: profile.id,
      profileName: profile.name,
      rememberProfile: true,
    });
    setError(null);
  };

  const deleteSavedProfile = async (profileId: string) => {
    try {
      await api.deleteProfile(profileId);
      setSavedProfiles((current) => current.filter((profile) => profile.id !== profileId));
      if (draft.profileId === profileId) {
        setDraft((current) => ({ ...current, profileId: undefined, profileName: "", password: "", rememberProfile: false }));
      }
    } catch (profileError) {
      setError(getErrorMessage(profileError));
    }
  };

  const runLookup = async (kind: LookupKind, names: string[], deviceGroup?: string) => {
    if (!connection) return;
    setLookupBusy(true);
    setLookupResult(null);
    setError(null);
    try {
      const result = demoMode && demoApi
        ? { found: [], requested: names, searchedScopes: 1, apiCalls: 1, elapsedMs: 20, partial: false, warnings: ["Lookup punktowy nie jest symulowany w trybie demo."] }
        : await api.lookup({ type: kind, names, deviceGroup, recentDays: recentHitDays });
      setLookupResult(result);
    } catch (lookupError) {
      setError(getErrorMessage(lookupError));
    } finally {
      setLookupBusy(false);
    }
  };

  const addLookupEntitiesToBatch = (entities: LookupEntity[]) => {
    const append = (current: string, names: string[]) => {
      const existing = parseNameInput(current).names;
      return [...new Set([...existing, ...names])].join("\n");
    };
    setObjectText((current) => append(current, entities.filter((item) => item.type === "address").map((item) => item.name)));
    setGroupText((current) => append(current, entities.filter((item) => item.type === "address-group").map((item) => item.name)));
    setPolicyText((current) => append(current, entities.filter((item) => item.type === "policy" && !item.readOnly).map((item) => item.name)));
  };

  const planDependencies = (dependencies: EntityDependency[], targets: AddressAnalysis[]) => {
    const append = (current: string, names: string[]) => [...new Set([...parseNameInput(current).names, ...names])].join("\n");
    const namesFor = (type: "address" | "address-group" | "policy") => [
      ...dependencies.filter((item) => item.type === type && !item.readOnly).map((item) => item.name),
      ...targets.filter((item) => item.targetType === ({ address: "address-object", "address-group": "address-group", policy: "policy" } as const)[type]).map((item) => item.label ?? item.ip.replace(/^[^:]+:/, "")),
    ];
    const targetIps = targets.filter((item) => (item.targetType ?? "ip") === "ip").map((item) => item.ip);
    setAddressText((current) => [...new Set([...parseAddressInput(current).addresses, ...targetIps])].join("\n"));
    setObjectText((current) => append(current, namesFor("address")));
    setGroupText((current) => append(current, namesFor("address-group")));
    setPolicyText((current) => append(current, namesFor("policy")));
    navigate("cleanup");
  };

  const analyze = async () => {
    if (!connection) return;
    setMainBusy("analyze");
    setAnalysisJob(null);
    setPolicyRequestPlan(null);
    setError(null);
    try {
      const addresses = parseAddressInput(addressText).addresses;
      const addressObjects = parseNameInput(objectText).names;
      const addressGroups = parseNameInput(groupText).names;
      const policies = parseNameInput(policyText).names;
      let plan: CleanupPlan;
      if (demoMode && demoApi) {
        plan = demoApi.demoCleanupPlan;
      } else {
        let job = await api.createCleanupAnalysisJob({ connectionId: connection.id, addresses, addressObjects, addressGroups, policies, runIcmp, recentHitDays, allowDefaultPolicyOverride });
        setAnalysisJob(job);
        while (job.state === "queued" || job.state === "running") {
          await wait(500);
          job = await api.getCleanupAnalysisJob(job.id);
          setAnalysisJob(job);
        }
        if (job.state === "failed" || !job.plan) {
          throw new Error(job.error?.message || "Backend nie zwrócił gotowego planu.");
        }
        plan = job.plan;
      }
      setCleanupPlan(plan);
      setExecutionSession(null);
      setExecutionJob(null);
      setView("plan");
    } catch (analysisError) {
      setError(getErrorMessage(analysisError));
    } finally {
      setMainBusy(null);
    }
  };

  const createSinglePlan = async (target: AddressAnalysis) => {
    if (!cleanupPlan || !target.componentId) return;
    setSinglePlanBusy(target.ip);
    setError(null);
    try {
      const plan = demoMode && demoApi
        ? demoApi.demoCleanupPlan
        : await api.createComponentPlan(cleanupPlan.sessionId, target.componentId, target.ip);
      setCleanupPlan(plan);
      setExecutionSession(null);
    } catch (singleError) {
      setError(getErrorMessage(singleError));
    } finally {
      setSinglePlanBusy(null);
    }
  };

  const createSelectionPlan = async (targets: AddressAnalysis[]) => {
    if (!cleanupPlan || !targets.length) return;
    setSinglePlanBusy("selection");
    setError(null);
    try {
      const plan = demoMode && demoApi
        ? demoApi.demoCleanupPlan
        : await api.createSelectionPlan(cleanupPlan.sessionId, targets.map((target) => target.ip));
      setCleanupPlan(plan);
      setExecutionSession(null);
      setExecutionJob(null);
    } catch (selectionError) {
      setError(getErrorMessage(selectionError));
    } finally {
      setSinglePlanBusy(null);
    }
  };

  const excludeTargets = async (targets: AddressAnalysis[]) => {
    if (!cleanupPlan || !targets.length) return;
    const busyKey = targets.length === 1 ? `exclude:${targets[0].ip}` : "exclude-selection";
    setSinglePlanBusy(busyKey);
    setError(null);
    try {
      const targetIds = targets.map((target) => target.ip);
      const plan = demoMode && demoApi
        ? demoApi.demoExclusionPlan(cleanupPlan, targetIds)
        : await api.createExclusionPlan(cleanupPlan.sessionId, targetIds);
      setCleanupPlan(plan);
      setExecutionSession(null);
      setExecutionJob(null);
    } catch (exclusionError) {
      setError(getErrorMessage(exclusionError));
    } finally {
      setSinglePlanBusy(null);
    }
  };

  const excludeComponents = async (componentIds: string[]) => {
    if (!cleanupPlan || !componentIds.length) return;
    setSinglePlanBusy(`exclude-component:${componentIds[0]}`);
    setError(null);
    try {
      const plan = demoMode && demoApi
        ? demoApi.demoExclusionPlan(cleanupPlan, [], componentIds)
        : await api.createExclusionPlan(cleanupPlan.sessionId, [], componentIds);
      setCleanupPlan(plan);
      setExecutionSession(null);
      setExecutionJob(null);
    } catch (exclusionError) {
      setError(getErrorMessage(exclusionError));
    } finally {
      setSinglePlanBusy(null);
    }
  };

  const undoLastExclusion = async () => {
    if (!cleanupPlan?.parentSessionId) return;
    setSinglePlanBusy("undo-exclusion");
    setError(null);
    try {
      const plan = demoMode && demoApi
        ? demoApi.demoCleanupPlan
        : await api.getCleanupPlan(cleanupPlan.parentSessionId);
      setCleanupPlan(plan);
      setExecutionSession(null);
      setExecutionJob(null);
    } catch (undoError) {
      setError(getErrorMessage(undoError));
    } finally {
      setSinglePlanBusy(null);
    }
  };

  const generateAdGroup = async () => {
    setMainBusy("ad-groups");
    setAdGroupResult(null);
    setError(null);
    try {
      const result = await api.generateAdGroup({
        groups: parseNameInput(adGroupDraft.groupsText).names,
        outputName: adGroupDraft.outputName,
        mappingName: adGroupDraft.mappingName,
        vsys: adGroupDraft.vsys,
        templateName: adGroupDraft.templateName,
      });
      setAdGroupResult(result);
    } catch (generationError) {
      setError(getErrorMessage(generationError));
    } finally {
      setMainBusy(null);
    }
  };

  const applyCandidate = async () => {
    if (!cleanupPlan) return;
    setStageBusy("candidate"); setExecutionJob(null); setError(null);
    try {
      if (demoMode && demoApi) {
        setExecutionSession(demoApi.demoAction(cleanupPlan.sessionId, "CANDIDATE_APPLIED", "candidate").session);
      } else {
        const started = await api.startCandidateJob(cleanupPlan.sessionId, { enableApiWrite: writeEnabled, executionStage: "push" });
        const job = await waitForExecutionJob(started, setExecutionJob);
        setExecutionSession(job.session);
      }
    } catch (actionError) { setError(getErrorMessage(actionError)); } finally { setStageBusy(null); }
  };

  const createPolicyRequestPlan = async (text: string) => {
    setMainBusy("policy-request");
    setError(null);
    try {
      const plan = demoMode && demoApi ? demoApi.demoCleanupPlan : await api.createPolicyRequestPlan(text);
      setPolicyRequestPlan(plan);
      setCleanupPlan(plan);
      setExecutionSession(null);
      setExecutionJob(null);
    } catch (policyError) {
      setError(getErrorMessage(policyError));
    } finally {
      setMainBusy(null);
    }
  };

  const commitCleanup = async (allowUnisolated: boolean, allowFull: boolean) => {
    if (!cleanupPlan) return;
    const sessionId = executionSession?.id ?? cleanupPlan.sessionId;
    setStageBusy("commit"); setExecutionJob(null); setError(null);
    try {
      if (demoMode && demoApi) {
        setExecutionSession(demoApi.demoAction(sessionId, "COMMITTED", "commit").session);
      } else {
        const started = await api.startCommitJob(sessionId, { enableApiWrite: writeEnabled, executionStage: "push", allowUnisolatedCommit: allowUnisolated, allowFullCommit: allowFull });
        const job = await waitForExecutionJob(started, setExecutionJob);
        setExecutionSession(job.session);
      }
    } catch (actionError) { setError(getErrorMessage(actionError)); } finally { setStageBusy(null); }
  };

  const pushCleanup = async () => {
    if (!cleanupPlan) return;
    const sessionId = executionSession?.id ?? cleanupPlan.sessionId;
    setStageBusy("push"); setExecutionJob(null); setError(null);
    try {
      if (demoMode && demoApi) {
        setExecutionSession(demoApi.demoAction(sessionId, "PUSHED", "push").session);
      } else {
        const started = await api.startPushJob(sessionId, cleanupPlan.affectedDeviceGroups, { enableApiWrite: writeEnabled, executionStage: "push" });
        const job = await waitForExecutionJob(started, setExecutionJob);
        setExecutionSession(job.session);
      }
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
      const current = selectedSession ? result.find((session) => session.id === selectedSession.id) : undefined;
      setSelectedSession(current ?? result.find((session) => session.kind === "cleanup" && session.canRestore) ?? result[0] ?? null);
    } catch (historyError) { setError(getErrorMessage(historyError)); } finally { setMainBusy(null); }
  }

  const openRestoreForSession = (session: ToolboxSession) => {
    setRestoreQuery(session.id);
    setRestorePlan(null);
    setRestoreSession(null);
    setRestoreExecutionJob(null);
    navigate("restore");
  };

  const openRestoreForTarget = (target: AddressAnalysis) => {
    setRestoreQuery(target.ip);
    setRestorePlan(null);
    setRestoreSession(null);
    setRestoreExecutionJob(null);
    navigate("restore");
  };

  const openRestoreForTargets = (targets: string[]) => {
    setRestoreQuery(targets.join("\n"));
    setRestorePlan(null);
    setRestoreSession(null);
    setRestoreExecutionJob(null);
    navigate("restore");
  };

  const downloadSessionBundle = async (session: ToolboxSession) => {
    setMainBusy("history"); setError(null);
    try {
      const blob = demoMode && demoApi ? new Blob([JSON.stringify(session, null, 2)], { type: "application/json" }) : await api.downloadSessionArtifact(session.id, "bundle");
      saveBlob(blob, `PanOS-Toolbox-${session.id}.${demoMode ? "json" : "zip"}`);
    } catch (downloadError) { setError(getErrorMessage(downloadError)); } finally { setMainBusy(null); }
  };

  const reconcileExternalSession = async (session: ToolboxSession) => {
    setMainBusy("history"); setError(null);
    try {
      const result = await api.reconcileExternalSession(session.id, "CLI");
      setSelectedSession(result.session);
      setSessions((current) => current.map((item) => item.id === result.session.id ? result.session : item));
    } catch (reconcileError) { setError(getErrorMessage(reconcileError)); } finally { setMainBusy(null); }
  };

  const createRestorePlan = async (mode: "target" | "session") => {
    if (!connection) return;
    setRestoreBusy("plan"); setError(null);
    try {
      const plan = demoMode && demoApi ? demoApi.demoRestorePlan : await api.createRestorePlan({ connectionId: connection.id, targets: mode === "target" ? parseNameInput(restoreQuery).names : undefined, sourceSessionId: mode === "session" ? restoreQuery.trim() : undefined });
      setRestorePlan(plan);
      setRestoreSession(null);
      setRestoreExecutionJob(null);
    } catch (planError) { setError(getErrorMessage(planError)); } finally { setRestoreBusy(null); }
  };

  const applyRestoreCandidate = async () => {
    if (!restorePlan) return;
    setRestoreBusy("candidate"); setRestoreExecutionJob(null); setError(null);
    try {
      if (demoMode && demoApi) {
        setRestoreSession(demoApi.demoAction(restorePlan.sessionId, "RESTORED", "restore").session);
      } else {
        const started = await api.startCandidateJob(restorePlan.sessionId, { enableApiWrite: writeEnabled, executionStage: "push" });
        const job = await waitForExecutionJob(started, setRestoreExecutionJob);
        setRestoreSession(job.session);
      }
    } catch (restoreError) { setError(getErrorMessage(restoreError)); } finally { setRestoreBusy(null); }
  };

  const commitRestore = async (allowUnisolated: boolean, allowFull: boolean) => {
    if (!restorePlan) return;
    const sessionId = restoreSession?.id ?? restorePlan.sessionId;
    setRestoreBusy("commit"); setRestoreExecutionJob(null); setError(null);
    try {
      if (demoMode && demoApi) {
        setRestoreSession(demoApi.demoAction(sessionId, "COMMITTED", "commit").session);
      } else {
        const started = await api.startCommitJob(sessionId, { enableApiWrite: writeEnabled, executionStage: "push", allowUnisolatedCommit: allowUnisolated, allowFullCommit: allowFull });
        const job = await waitForExecutionJob(started, setRestoreExecutionJob);
        setRestoreSession(job.session);
      }
    } catch (restoreError) { setError(getErrorMessage(restoreError)); } finally { setRestoreBusy(null); }
  };

  const pushRestore = async () => {
    if (!restorePlan) return;
    const sessionId = restoreSession?.id ?? restorePlan.sessionId;
    const groups = restorePlan.affectedDeviceGroups;
    setRestoreBusy("push"); setRestoreExecutionJob(null); setError(null);
    try {
      if (demoMode && demoApi) {
        setRestoreSession(demoApi.demoAction(sessionId, "PUSHED", "push").session);
      } else {
        const started = await api.startPushJob(sessionId, groups, { enableApiWrite: writeEnabled, executionStage: "push" });
        const job = await waitForExecutionJob(started, setRestoreExecutionJob);
        setRestoreSession(job.session);
      }
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
  if (view === "connection") page = <ConnectionPage draft={draft} onDraftChange={setDraft} savedProfiles={savedProfiles} profileStorage={profileStorage} connection={connection} doctor={doctor} busy={mainBusy === "connect" || mainBusy === "doctor" ? mainBusy : null} error={error} onConnect={() => void connect()} onDoctor={() => void runDoctor()} onSelectProfile={selectSavedProfile} onDeleteProfile={(profileId) => void deleteSavedProfile(profileId)} onDemo={enableDemo} demoAvailable={import.meta.env.DEV} />;
  else if (view === "cleanup") page = <CleanupPage connection={connection} targetTexts={{ ip: addressText, object: objectText, group: groupText, policy: policyText }} onTargetTextChange={(kind, value) => ({ ip: setAddressText, object: setObjectText, group: setGroupText, policy: setPolicyText })[kind](value)} runIcmp={runIcmp} onRunIcmpChange={setRunIcmp} recentHitDays={recentHitDays} onRecentHitDaysChange={setRecentHitDays} allowDefaultPolicyOverride={allowDefaultPolicyOverride} onDefaultPolicyOverrideChange={setAllowDefaultPolicyOverride} busy={mainBusy === "analyze"} progress={analysisJob} lookupResult={lookupResult} lookupBusy={lookupBusy} error={error} onLookup={(kind, names, deviceGroup) => void runLookup(kind, names, deviceGroup)} onAddLookupEntities={addLookupEntitiesToBatch} onAnalyze={() => void analyze()} onOpenConnection={() => navigate("connection")} onOpenWarnings={() => navigate("warnings")} />;
  else if (view === "warnings") page = <WarningsPage notices={notices} />;
  else if (view === "ad-groups") page = <AdGroupsPage draft={adGroupDraft} onDraftChange={setAdGroupDraft} result={adGroupResult} busy={mainBusy === "ad-groups"} error={error} onGenerate={() => void generateAdGroup()} />;
  else if (view === "policy-requests") page = <PolicyRequestsPage connection={Boolean(connection)} busy={mainBusy === "policy-request"} error={error} plan={policyRequestPlan} onCreatePlan={(text) => void createPolicyRequestPlan(text)} onOpenConnection={() => navigate("connection")} onOpenPlan={() => navigate("plan")} />;
  else if (view === "plan" || view === "execute") page = <PlanPage focus={view} plan={cleanupPlan} executionSession={executionSession} executionJob={executionJob} writeEnabled={writeEnabled} busy={stageBusy} singlePlanBusy={singlePlanBusy} error={error} onOpenCleanup={() => navigate("cleanup")} onCreateSinglePlan={(target) => void createSinglePlan(target)} onCreateSelectionPlan={(targets) => void createSelectionPlan(targets)} onExcludeTargets={(targets) => void excludeTargets(targets)} onExcludeComponents={(componentIds) => void excludeComponents(componentIds)} onUndoLastExclusion={() => void undoLastExclusion()} onPlanDependencies={planDependencies} onRestoreTarget={openRestoreForTarget} onApplyCandidate={() => void applyCandidate()} onCommit={() => void commitCleanup(true, false)} onPush={() => void pushCleanup()} onDownload={(artifact) => void downloadCleanup(artifact)} />;
  else if (view === "audit") page = <AuditPage connection={connection} query={auditQuery} onQueryChange={setAuditQuery} result={auditResult} busy={mainBusy === "audit"} error={error} onAudit={() => void runAudit()} onOpenConnection={() => navigate("connection")} />;
  else if (view === "history") page = <HistoryPage sessions={sessions} selected={selectedSession} busy={mainBusy === "history"} error={error} onRefresh={() => void refreshHistory()} onSelect={setSelectedSession} onRestore={openRestoreForSession} onRestoreTargets={openRestoreForTargets} onDownloadBundle={(session) => void downloadSessionBundle(session)} onReconcileExternal={(session) => void reconcileExternalSession(session)} />;
  else page = <RestorePage query={restoreQuery} onQueryChange={setRestoreQuery} plan={restorePlan} executionSession={restoreSession} executionJob={restoreExecutionJob} writeEnabled={writeEnabled} connected={Boolean(connection)} busy={restoreBusy} error={error} onCreatePlan={(mode) => void createRestorePlan(mode)} onApplyCandidate={() => void applyRestoreCandidate()} onCommit={() => void commitRestore(true, false)} onPush={() => void pushRestore()} onDownloadConflicts={() => void downloadConflicts()} onOpenConnection={() => navigate("connection")} onOpenWarnings={() => navigate("warnings")} />;

  return (
    <Shell activeView={view} onViewChange={navigate} connection={connection} writeEnabled={writeEnabled} onWriteEnabledChange={setWriteEnabled} theme={theme} onThemeChange={() => setTheme((current) => current === "dark" ? "light" : "dark")} onDisconnect={() => void disconnect()} demoMode={demoMode} warningCount={notices.length}>
      {page}
    </Shell>
  );
}
