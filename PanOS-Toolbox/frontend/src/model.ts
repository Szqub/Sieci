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
}

export interface ConnectionSession {
  id: string;
  host: string;
  username: string;
  panoramaVersion: string;
  apiMaxStage: CapabilityStage;
  connectedAt: string;
  candidateDirty: boolean;
  capabilityWarning?: string;
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
export type Decision = "process" | "skip-live" | "skip-error" | "not-found" | "blocked";

export interface ReferenceLocation {
  id: string;
  scope: string;
  deviceGroup: string;
  rulebase: "pre" | "post" | "local" | "shared";
  policyType: "security" | "nat" | "application-override" | "group" | "object";
  name: string;
  field: string;
  path: string;
}

export interface AddressAnalysis {
  ip: string;
  label?: string;
  targetType?: "ip" | "address-object" | "address-group" | "policy";
  objectNames: string[];
  icmp: IcmpState;
  icmpDetail?: string;
  decision: Decision;
  lastHit?: string;
  lastHitStatus?: string;
  lastHitDetail?: string;
  recentLastHit: boolean;
  componentId?: string;
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
  recentHitCount: number;
  affectedDeviceGroups: string[];
  diff: DiffSummary;
  warnings: string[];
  addresses: AddressAnalysis[];
  operations: PatchOperation[];
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
  kind: "cleanup" | "restore";
  state: SessionState;
  createdAt: string;
  updatedAt: string;
  operator: string;
  panoramaHost: string;
  itemCount: number;
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
