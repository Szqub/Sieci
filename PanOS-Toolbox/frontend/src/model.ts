export type CapabilityStage = "read-only" | "candidate" | "commit" | "push";

export type SessionState =
  | "PLANNED"
  | "WRITING_CANDIDATE"
  | "CANDIDATE_APPLIED"
  | "COMMITTING"
  | "COMMITTED"
  | "PUSHING"
  | "PUSHED"
  | "RESTORING"
  | "RESTORED"
  | "PARTIAL"
  | "FAILED"
  | "CONFLICT"
  | "OUTCOME_UNKNOWN";

export type Severity = "info" | "warning" | "danger" | "success";

export interface ConnectionDraft {
  host: string;
  username: string;
  password: string;
  ssl: boolean;
  verifySsl: boolean;
  apiMaxStage: CapabilityStage;
  profileId?: string;
  profileName?: string;
  rememberProfile?: boolean;
}

export interface SavedProfile {
  id: string;
  name: string;
  host: string;
  username: string;
  ssl: boolean;
  verifySsl: boolean;
  apiMaxStage: CapabilityStage;
  hasPassword: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ConnectionSession {
  id: string;
  host: string;
  username: string;
  panoramaVersion: string;
  apiMaxStage: CapabilityStage;
  connectedAt: string;
  candidateDirty: boolean;
  candidateStatus?: "clean" | "dirty" | "unknown";
  capabilityWarning?: string;
  profileId?: string;
  profileSaved?: boolean;
}

export type LookupKind = "address" | "address-group" | "policy" | "ip";

export interface LookupField {
  k: string;
  v: string;
}

export interface LookupEntity {
  id: string;
  type: "address" | "address-group" | "policy";
  name: string;
  value: string;
  scope: string;
  rulebase?: "pre-rulebase" | "post-rulebase";
  policyType?: "security" | "nat" | "application-override";
  xpath: string;
  readOnly: boolean;
  blockedReason?: string;
  fields: LookupField[];
  dependencies: EntityDependency[];
  hitCount?: number;
  lastHit?: string;
  lastHitStatus?: string;
  lastHitAgeDays?: number;
  lastHitDetail?: string;
}

export interface LookupResult {
  found: LookupEntity[];
  requested: string[];
  searchedScopes: number;
  apiCalls: number;
  elapsedMs: number;
  partial: boolean;
  warnings: string[];
}

export interface DoctorCheck {
  id: string;
  label: string;
  detail: string;
  state: "pass" | "warn" | "fail" | "pending";
  durationMs?: number;
}

export interface DoctorResult {
  checks: DoctorCheck[];
  generatedAt: string;
}

export interface DiffSummary {
  nativeChanged: boolean;
  semanticChanged: boolean;
  nativeEntries: number;
  semanticEntries: number;
  summary: string;
  diagnosticMismatch: boolean;
}

export type IcmpState = "responded" | "timeout" | "error" | "not-run";
export type Decision = "process" | "skip-live" | "skip-error" | "not-found" | "blocked" | "excluded";

export interface ReferenceLocation {
  id: string;
  type?: string;
  scope: string;
  deviceGroup: string;
  rulebase?: "pre-rulebase" | "post-rulebase" | "pre" | "post" | "local" | "shared";
  policyType?: "security" | "nat" | "application-override" | "group" | "object";
  name: string;
  field: string;
  relation?: string;
  path: string;
  readOnly?: boolean;
  hitCount?: number;
  lastHit?: string;
  lastHitStatus?: string;
  lastHitAgeDays?: number;
  lastHitDetail?: string;
}

export interface EntityDependency extends ReferenceLocation {
  type: string;
}

export interface EntityInspection {
  id: string;
  type: string;
  name: string;
  scope: string;
  rulebase?: string;
  policyType?: string;
  path: string;
  readOnly: boolean;
  blockedReason?: string;
  fields: LookupField[];
  dependencies: EntityDependency[];
  hitCount?: number;
  lastHit?: string;
  lastHitStatus?: string;
  lastHitAgeDays?: number;
  lastHitDetail?: string;
}

export interface EntityBackup {
  mutationId: string;
  entityType: string;
  entityName: string;
  file: string;
  sha256: string;
}

export interface AddressAnalysis {
  ip: string;
  label?: string;
  targetType?: "ip" | "address-object" | "address-group" | "policy";
  objectNames: string[];
  icmp: IcmpState;
  icmpDetail?: string;
  decision: Decision;
  excludedByUser?: boolean;
  defaultPolicyProtected?: boolean;
  exclusionReason?: string;
  lastHit?: string;
  hitCount?: number;
  lastHitAgeDays?: number;
  lastHitStatus?: string;
  lastHitDetail?: string;
  recentLastHit: boolean;
  componentId?: string;
  componentIds?: string[];
  operationIds?: string[];
  entities?: EntityInspection[];
  backupFiles?: EntityBackup[];
  references: ReferenceLocation[];
}

export type PatchAction = "set" | "edit" | "delete" | "move";

export interface PatchOperation {
  id: string;
  componentId: string;
  order: number;
  action: PatchAction;
  entityType: "address" | "address-group" | "policy" | "member";
  entityName: string;
  scope: string;
  xpath: string;
  summary: string;
  inverseSummary: string;
  fingerprint: string;
}

export interface CleanupPlan {
  id: string;
  sessionId: string;
  createdAt: string;
  state: SessionState;
  sourceCount: number;
  processCount: number;
  skippedLiveCount: number;
  skippedErrorCount: number;
  notFoundCount: number;
  excludedCount?: number;
  excludedTargets?: string[];
  exclusionImpactedTargets?: string[];
  excludedComponentIds?: string[];
  parentSessionId?: string;
  kind?: "cleanup" | "restore" | "future-create";
  defaultPolicyOverride?: boolean;
  recentHitCount: number;
  affectedDeviceGroups: string[];
  diff: DiffSummary;
  warnings: string[];
  addresses: AddressAnalysis[];
  operations: PatchOperation[];
}

export interface AnalysisJob {
  id: string;
  state: "queued" | "running" | "success" | "failed";
  progress: number;
  message: string;
  plan?: CleanupPlan;
  error?: ApiErrorPayload;
}

export interface ExecutionProgressItem {
  event: string;
  message?: string;
  progress?: number;
  sequence?: number;
  timestamp?: string;
  mutationId?: string;
  entityType?: string;
  entityKey?: string;
  action?: string;
  xpath?: string;
  completedOperations?: number;
  totalOperations?: number;
  backupCount?: number;
  jobId?: string;
  status?: string;
  result?: string;
  panoramaProgress?: number;
  details?: string;
  pollCount?: number;
  elapsedSeconds?: number;
}

export interface ExecutionJob {
  id: string;
  sessionId: string;
  kind: "candidate" | "commit" | "push";
  state: "queued" | "running" | "success" | "failed";
  progress: number;
  message: string;
  current?: ExecutionProgressItem;
  items: ExecutionProgressItem[];
  session?: ToolboxSession;
  error?: ApiErrorPayload;
  startedAt?: string;
  finishedAt?: string;
}

export interface ToolboxNotice {
  id: string;
  source: string;
  title: string;
  detail: string;
  severity: "info" | "warning" | "danger";
  context?: string;
}

export type AdGroupStatus = "valid" | "empty" | "not-found" | "error";

export interface AdGroupValidation {
  name: string;
  status: AdGroupStatus;
  memberCount: number;
  distinguishedName?: string;
  detail: string;
}

export interface AdFilterBlock {
  index: number;
  filter: string;
  sourceGroups: string[];
}

export interface AdGroupGenerationResult {
  generatedAt: string;
  outputGroupName: string;
  mappingName: string;
  vsys: string;
  templateName: string;
  panoramaPath: string;
  chunkSize: number;
  inputCount: number;
  validCount: number;
  skippedCount: number;
  groups: AdGroupValidation[];
  blocks: AdFilterBlock[];
  clipboardText: string;
  warnings: string[];
}

export interface JobStatus {
  id: string;
  kind: "candidate" | "validation" | "commit" | "push" | "restore";
  state: "queued" | "running" | "success" | "failed";
  progress: number;
  message: string;
  startedAt: string;
  finishedAt?: string;
}

export interface ToolboxSession {
  id: string;
  kind: "cleanup" | "restore" | "future-create";
  state: SessionState;
  createdAt: string;
  updatedAt: string;
  operator: string;
  panoramaHost: string;
  itemCount: number;
  targets?: string[];
  backupCount?: number;
  backupItems?: Array<EntityBackup & { targets: string[]; componentId?: string }>;
  canRestore?: boolean;
  canReconcileExternal?: boolean;
  executionSource?: "GUI" | "CLI" | "API";
  affectedDeviceGroups: string[];
  sourceSessionId?: string;
  sourceSessionIds?: string[];
  description: string;
  jobs: JobStatus[];
}

export interface AuditResult {
  generatedAt: string;
  addresses: AddressAnalysis[];
  residualReferenceCount: number;
  cleanCount: number;
}

export interface RestoreEntity {
  id: string;
  componentId: string;
  type: "address" | "address-group" | "policy" | "member";
  name: string;
  scope: string;
  outcome: "restore" | "already-present" | "conflict";
  detail: string;
}

export interface RestorePlan {
  id: string;
  sessionId: string;
  sourceSessionId: string;
  sourceSessionIds?: string[];
  query: string;
  createdAt: string;
  state: SessionState;
  safeComponentCount: number;
  conflictComponentCount: number;
  affectedDeviceGroups: string[];
  entities: RestoreEntity[];
  warnings: string[];
  operations: PatchOperation[];
}

export interface WriteOptions {
  enableApiWrite: boolean;
  executionStage: CapabilityStage;
  allowUnisolatedCommit?: boolean;
  allowFullCommit?: boolean;
}

export interface ApiActionResult {
  session: ToolboxSession;
  job?: JobStatus;
  message: string;
}

export interface ApiErrorPayload {
  code?: string;
  message?: string;
  detail?: string;
  correlation_id?: string;
}

export const stageOrder: Record<CapabilityStage, number> = {
  "read-only": 0,
  candidate: 1,
  commit: 2,
  push: 3,
};

export function stageAllows(maximum: CapabilityStage, requested: CapabilityStage): boolean {
  return stageOrder[maximum] >= stageOrder[requested];
}

export function formatDate(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("pl-PL", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}
