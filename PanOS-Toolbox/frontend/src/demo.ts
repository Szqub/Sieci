import type {
  ApiActionResult,
  AuditResult,
  CleanupPlan,
  CommitReview,
  ConnectionDraft,
  ConnectionSession,
  DoctorResult,
  JobStatus,
  RestorePlan,
  SessionState,
  ToolboxSession,
} from "./model";

const stamp = "2026-07-15T10:28:00+02:00";

const demoCommitReview: CommitReview = {
  schemaVersion: 1,
  sessionId: "cleanup-20260715-1028-7ea94f",
  generatedAt: stamp,
  commitReady: true,
  running: { rawSha256: "demo-running", semanticSha256: "demo-running-semantic" },
  candidate: { rawSha256: "demo-candidate", semanticSha256: "demo-candidate-semantic" },
  native: { available: true, has_changes: true, detail: "6 zmian candidate" },
  summary: { total: 6, planned: 6, outsidePlan: 0, added: 0, removed: 5, changed: 1 },
  scopeGuard: { passed: true, findingCount: 0, outsidePlanCount: 0, checkedMutationCount: 6, candidateProjectionMatches: true, findings: [] },
  changes: [
    { key: "DG-PROD-EU/address/srv-legacy-01", change: "removed", entityType: "address", scope: "DG-PROD-EU", name: "srv-legacy-01", xpath: "/config/.../address/srv-legacy-01", planned: true, explanation: "Encja zostanie usunięta z candidate.", mutationIds: ["mutation-00003"], componentIds: ["component-a"], causes: ["10.42.16.19"], operations: [{ mutationId: "mutation-00003", action: "delete", xpath: "/config/.../address/srv-legacy-01" }] },
  ],
  artifacts: { reviewJson: "pre_commit_review_demo.json", reviewText: "pre_commit_review_demo.txt", candidateDiff: "candidate_diff_demo.txt", scopeGuard: "scope_guard_demo.txt" },
};

const demoArtifacts = [
  { file: "commands.txt", kind: "handmode-cli-active", contentType: "text/plain; charset=utf-8", sizeBytes: 2048, viewable: true, downloadable: true },
  { file: "handmode_rollback.txt", kind: "handmode-cli-rollback", contentType: "text/plain; charset=utf-8", sizeBytes: 3072, viewable: true, downloadable: true },
  { file: "handmode_instructions.txt", kind: "handmode-instructions", contentType: "text/plain; charset=utf-8", sizeBytes: 1024, viewable: true, downloadable: true },
  { file: "candidate_diff_demo.txt", kind: "full-running-candidate-diff", contentType: "text/plain; charset=utf-8", sizeBytes: 4096, viewable: true, downloadable: true },
  { file: "manifest.json", kind: "manifest", contentType: "application/json; charset=utf-8", sizeBytes: 8192, viewable: true, downloadable: true },
  { file: "bundle", kind: "complete-session-zip", contentType: "application/zip", viewable: false, downloadable: true },
];

export function demoConnection(input: ConnectionDraft): ConnectionSession {
  return {
    id: "conn-demo-7ea94f",
    host: input.host || "panorama.lab.local",
    username: input.username || "superadmin",
    panoramaVersion: "10.2.16-h4",
    apiMaxStage: input.apiMaxStage,
    connectedAt: stamp,
    candidateDirty: true,
  };
}

export const demoDoctor: DoctorResult = {
  generatedAt: stamp,
  checks: [
    { id: "loopback", label: "Lokalny serwer", detail: "127.0.0.1 · dostępny", state: "pass", durationMs: 2 },
    { id: "storage", label: "Katalog sesji", detail: "ACL ograniczone do bieżącego użytkownika", state: "pass", durationMs: 8 },
    { id: "panorama", label: "Panorama XML API", detail: "Połączenie oraz keygen działają", state: "pass", durationMs: 184 },
    { id: "diff", label: "Candidate change-summary", detail: "7 istniejących zmian — informacja, nie blokada", state: "warn", durationMs: 96 },
  ],
};

export const demoCleanupPlan: CleanupPlan = {
  id: "plan-20260715-01",
  sessionId: "cleanup-20260715-1028-7ea94f",
  createdAt: stamp,
  state: "PLANNED",
  sourceCount: 6,
  processCount: 3,
  skippedLiveCount: 1,
  skippedErrorCount: 1,
  notFoundCount: 1,
  recentHitCount: 1,
  affectedDeviceGroups: ["DG-PROD-EU", "DG-SHARED-SERVICES"],
  diff: {
    nativeChanged: true,
    semanticChanged: true,
    nativeEntries: 7,
    semanticEntries: 7,
    summary: "Candidate zawiera 7 wcześniejszych zmian operatora. Plan dotyka innych ścieżek XPath.",
    diagnosticMismatch: false,
  },
  warnings: [
    "Obiekt srv-legacy-03 wystąpił w regule z Last Hit sprzed 4 dni.",
    "Jedno sprawdzenie ICMP zakończyło się błędem lokalnym — adres został bezpiecznie pominięty.",
  ],
  addresses: [
    {
      ip: "10.42.16.19",
      objectNames: ["srv-legacy-01"],
      icmp: "timeout",
      icmpDetail: "Brak odpowiedzi po 3 próbach",
      decision: "process",
      recentLastHit: false,
      lastHit: "2026-05-12T09:21:00+02:00",
      componentId: "component-a",
      references: [
        { id: "r1", scope: "device-group", deviceGroup: "DG-PROD-EU", rulebase: "pre", policyType: "security", name: "Allow-Legacy-API", field: "source", path: "/config/devices/entry/device-group/entry[@name='DG-PROD-EU']/pre-rulebase/security/rules/entry[@name='Allow-Legacy-API']/source" },
        { id: "r2", scope: "device-group", deviceGroup: "DG-PROD-EU", rulebase: "pre", policyType: "group", name: "GRP-Legacy-Servers", field: "static", path: "/config/devices/entry/device-group/entry[@name='DG-PROD-EU']/address-group/entry[@name='GRP-Legacy-Servers']/static" },
      ],
    },
    {
      ip: "10.42.16.20",
      objectNames: ["srv-legacy-02"],
      icmp: "timeout",
      decision: "process",
      recentLastHit: false,
      lastHit: "2026-04-29T14:13:00+02:00",
      componentId: "component-a",
      references: [
        { id: "r3", scope: "device-group", deviceGroup: "DG-PROD-EU", rulebase: "pre", policyType: "group", name: "GRP-Legacy-Servers", field: "static", path: "/config/devices/entry/device-group/entry[@name='DG-PROD-EU']/address-group/entry[@name='GRP-Legacy-Servers']/static" },
      ],
    },
    {
      ip: "10.42.16.21",
      objectNames: ["srv-legacy-03"],
      icmp: "timeout",
      decision: "process",
      recentLastHit: true,
      lastHit: "2026-07-11T18:42:00+02:00",
      componentId: "component-b",
      references: [
        { id: "r4", scope: "device-group", deviceGroup: "DG-SHARED-SERVICES", rulebase: "post", policyType: "nat", name: "DNAT-Legacy-03", field: "source-translation", path: "/config/devices/entry/device-group/entry[@name='DG-SHARED-SERVICES']/post-rulebase/nat/rules/entry[@name='DNAT-Legacy-03']" },
        { id: "r5", scope: "device-group", deviceGroup: "DG-SHARED-SERVICES", rulebase: "pre", policyType: "application-override", name: "Override-Old-App", field: "source", path: "/config/devices/entry/device-group/entry[@name='DG-SHARED-SERVICES']/pre-rulebase/application-override/rules/entry[@name='Override-Old-App']/source" },
      ],
    },
    { ip: "10.42.16.22", objectNames: ["srv-live-01"], icmp: "responded", icmpDetail: "Odpowiedź 4 ms", decision: "skip-live", recentLastHit: false, references: [] },
    { ip: "10.42.16.23", objectNames: ["srv-icmp-unknown"], icmp: "error", icmpDetail: "Brak uprawnień do procesu ping", decision: "skip-error", recentLastHit: false, references: [] },
    { ip: "10.42.16.99", objectNames: [], icmp: "timeout", decision: "not-found", recentLastHit: false, references: [] },
  ],
  operations: [
    { id: "op-1", componentId: "component-a", order: 1, action: "edit", entityType: "policy", entityName: "Allow-Legacy-API", scope: "DG-PROD-EU · pre/security", xpath: "/config/.../Allow-Legacy-API/source", summary: "Usuń GRP-Legacy-Servers ze source; reguła ma inne źródła", inverseSummary: "Przywróć GRP-Legacy-Servers na pierwotnej pozycji", fingerprint: "sha256:15d9…38a1" },
    { id: "op-2", componentId: "component-a", order: 2, action: "delete", entityType: "address-group", entityName: "GRP-Legacy-Servers", scope: "DG-PROD-EU", xpath: "/config/.../address-group/GRP-Legacy-Servers", summary: "Usuń pustą grupę adresową", inverseSummary: "Odtwórz grupę oraz pełną kolejność członków", fingerprint: "sha256:949e…af08" },
    { id: "op-3", componentId: "component-a", order: 3, action: "delete", entityType: "address", entityName: "srv-legacy-01", scope: "DG-PROD-EU", xpath: "/config/.../address/srv-legacy-01", summary: "Usuń obiekt 10.42.16.19", inverseSummary: "Odtwórz pełny XML obiektu", fingerprint: "sha256:c610…20e7" },
    { id: "op-4", componentId: "component-a", order: 4, action: "delete", entityType: "address", entityName: "srv-legacy-02", scope: "DG-PROD-EU", xpath: "/config/.../address/srv-legacy-02", summary: "Usuń obiekt 10.42.16.20", inverseSummary: "Odtwórz pełny XML obiektu", fingerprint: "sha256:19af…0ef2" },
    { id: "op-5", componentId: "component-b", order: 5, action: "delete", entityType: "policy", entityName: "DNAT-Legacy-03", scope: "DG-SHARED-SERVICES · post/nat", xpath: "/config/.../nat/DNAT-Legacy-03", summary: "Usuń regułę NAT, ponieważ obiekt jest jedynym źródłem", inverseSummary: "Odtwórz regułę 1:1 i przesuń przed Drop-RFC1918", fingerprint: "sha256:a402…cd17" },
    { id: "op-6", componentId: "component-b", order: 6, action: "delete", entityType: "address", entityName: "srv-legacy-03", scope: "DG-SHARED-SERVICES", xpath: "/config/.../address/srv-legacy-03", summary: "Usuń obiekt 10.42.16.21", inverseSummary: "Odtwórz pełny XML obiektu", fingerprint: "sha256:11b2…c748" },
  ],
  commitReview: demoCommitReview,
  artifacts: demoArtifacts,
};

export function demoExclusionPlan(plan: CleanupPlan, targets: string[], componentIds: string[] = []): CleanupPlan {
  const requested = new Set(targets);
  const removedComponents = new Set(
    [
      ...componentIds,
      ...plan.addresses
      .filter((target) => requested.has(target.ip))
      .flatMap((target) => target.componentIds ?? (target.componentId ? [target.componentId] : [])),
    ],
  );
  const impacted = new Set(plan.exclusionImpactedTargets ?? []);
  let changed = true;
  while (changed) {
    changed = false;
    for (const target of plan.addresses) {
      const components = target.componentIds ?? (target.componentId ? [target.componentId] : []);
      if (!components.some((component) => removedComponents.has(component))) continue;
      if (!impacted.has(target.ip)) { impacted.add(target.ip); changed = true; }
      for (const component of components) {
        if (!removedComponents.has(component)) { removedComponents.add(component); changed = true; }
      }
    }
  }
  const excluded = new Set([...(plan.excludedTargets ?? []), ...targets]);
  const addresses = plan.addresses.map((target) => impacted.has(target.ip)
    ? {
        ...target,
        decision: "excluded" as const,
        excludedByUser: excluded.has(target.ip),
        exclusionReason: excluded.has(target.ip)
          ? "Wykluczony ręcznie przez operatora."
          : "Wykluczony razem z atomowym komponentem zależności.",
        operationIds: [],
        backupFiles: [],
      }
    : target);
  return {
    ...plan,
    id: `${plan.id}-excluded`,
    sessionId: `${plan.sessionId}-excluded`,
    parentSessionId: plan.sessionId,
    processCount: addresses.filter((target) => target.decision === "process").length,
    excludedCount: impacted.size,
    excludedTargets: [...excluded],
    exclusionImpactedTargets: [...impacted],
    excludedComponentIds: [...new Set([...(plan.excludedComponentIds ?? []), ...removedComponents])],
    addresses,
    operations: plan.operations.filter((operation) => !removedComponents.has(operation.componentId)),
    warnings: [...plan.warnings, `Wykluczono ${targets.length} wskazanych celów z wykonania.`],
  };
}

function job(id: string, kind: JobStatus["kind"], state: JobStatus["state"], progress: number): JobStatus {
  return { id, kind, state, progress, message: state === "success" ? "Zakończono poprawnie" : "Oczekiwanie na Panorama", startedAt: stamp, finishedAt: state === "success" ? stamp : undefined };
}

export const demoSessions: ToolboxSession[] = [
  { id: demoCleanupPlan.sessionId, kind: "cleanup", state: "PLANNED", createdAt: stamp, updatedAt: stamp, operator: "superadmin", panoramaHost: "panorama.lab.local", itemCount: 3, affectedDeviceGroups: ["DG-PROD-EU", "DG-SHARED-SERVICES"], description: "Cleanup 3 z 6 adresów", jobs: [] },
  { id: "cleanup-20260714-1642-8ea184", kind: "cleanup", state: "PUSHED", createdAt: "2026-07-14T16:42:00+02:00", updatedAt: "2026-07-14T16:51:00+02:00", operator: "netops", panoramaHost: "panorama.lab.local", itemCount: 18, affectedDeviceGroups: ["DG-OFFICE"], description: "Cleanup 18 adresów", jobs: [job("8051", "commit", "success", 100), job("8052", "push", "success", 100)] },
  { id: "restore-20260714-1021-176f41", kind: "restore", state: "RESTORED", createdAt: "2026-07-14T10:21:00+02:00", updatedAt: "2026-07-14T10:26:00+02:00", operator: "superadmin", panoramaHost: "panorama.lab.local", itemCount: 1, affectedDeviceGroups: ["DG-PROD-EU"], sourceSessionId: "cleanup-20260713-1550-4f201d", description: "Emergency Restore 10.42.8.17", jobs: [job("8012", "restore", "success", 100)] },
  { id: "cleanup-20260712-0904-ab7901", kind: "cleanup", state: "CONFLICT", createdAt: "2026-07-12T09:04:00+02:00", updatedAt: "2026-07-12T09:08:00+02:00", operator: "netops", panoramaHost: "panorama.lab.local", itemCount: 4, affectedDeviceGroups: ["DG-DMZ"], description: "Cleanup zatrzymany przez konflikt XPath", jobs: [] },
];

export const demoAudit: AuditResult = {
  generatedAt: stamp,
  residualReferenceCount: 3,
  cleanCount: 1,
  addresses: [demoCleanupPlan.addresses[0], demoCleanupPlan.addresses[2], { ...demoCleanupPlan.addresses[5], references: [] }],
};

export const demoRestorePlan: RestorePlan = {
  id: "restore-plan-b719e0",
  sessionId: "restore-20260715-1132-b719e0",
  sourceSessionId: "cleanup-20260714-1642-8ea184",
  query: "10.42.8.17",
  createdAt: stamp,
  state: "PLANNED",
  safeComponentCount: 2,
  conflictComponentCount: 1,
  affectedDeviceGroups: ["DG-PROD-EU"],
  warnings: ["Komponent z regułą Allow-Payments zmienił się po cleanupie i nie zostanie nadpisany."],
  entities: [
    { id: "e1", componentId: "safe-1", type: "address", name: "payments-node-01", scope: "DG-PROD-EU", outcome: "restore", detail: "Bieżący stan odpowiada oczekiwanemu stanowi po cleanupie" },
    { id: "e2", componentId: "safe-1", type: "address-group", name: "GRP-Payments-Nodes", scope: "DG-PROD-EU", outcome: "restore", detail: "Zostanie odtworzony brakujący członek; późniejsze członki pozostaną" },
    { id: "e3", componentId: "safe-2", type: "policy", name: "DNAT-Payments", scope: "DG-PROD-EU · pre/nat", outcome: "already-present", detail: "Reguła została już odtworzona ręcznie i jest zgodna z backupem" },
    { id: "e4", componentId: "conflict-1", type: "policy", name: "Allow-Payments", scope: "DG-PROD-EU · pre/security", outcome: "conflict", detail: "Current różni się jednocześnie od base i expected — wymaga ręcznej decyzji" },
  ],
  operations: [
    { id: "rop-1", componentId: "safe-1", order: 1, action: "set", entityType: "address", entityName: "payments-node-01", scope: "DG-PROD-EU", xpath: "/config/.../address/payments-node-01", summary: "Odtwórz obiekt z backupu sesji", inverseSummary: "Usuń odtworzony obiekt", fingerprint: "sha256:fa80…c17f" },
    { id: "rop-2", componentId: "safe-1", order: 2, action: "edit", entityType: "member", entityName: "GRP-Payments-Nodes", scope: "DG-PROD-EU", xpath: "/config/.../GRP-Payments-Nodes/static", summary: "Dodaj brakujący członek bez usuwania późniejszych", inverseSummary: "Usuń wyłącznie dodany członek", fingerprint: "sha256:c078…45bd" },
  ],
  artifacts: [
    ...demoArtifacts,
    { file: "handmode_conflict_restore_commands.txt", kind: "handmode-cli-conflict-restore-manual-review", contentType: "text/plain; charset=utf-8", sizeBytes: 1024, viewable: true, downloadable: true },
    { file: "handmode_conflict_restore_rollback.txt", kind: "handmode-cli-conflict-restore-rollback", contentType: "text/plain; charset=utf-8", sizeBytes: 1024, viewable: true, downloadable: true },
    { file: "handmode_conflict_restore_instructions.txt", kind: "handmode-conflict-restore-instructions", contentType: "text/plain; charset=utf-8", sizeBytes: 768, viewable: true, downloadable: true },
  ],
};

export function demoAction(sessionId: string, targetState: SessionState, kind: JobStatus["kind"]): ApiActionResult {
  const resultJob = job(`${kind}-demo-01`, kind, "success", 100);
  return {
    message: `${kind} zakończony w trybie demonstracyjnym.`,
    job: resultJob,
    session: {
      ...(demoSessions.find((entry) => entry.id === sessionId) ?? demoSessions[0]),
      id: sessionId,
      state: targetState,
      updatedAt: stamp,
      jobs: [resultJob],
      commitReview: demoCommitReview,
      artifacts: demoArtifacts,
    },
  };
}
