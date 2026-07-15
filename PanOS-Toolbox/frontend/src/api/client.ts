import type {
  ApiActionResult,
  ApiErrorPayload,
  AuditResult,
  CapabilityStage,
  CleanupPlan,
  ConnectionDraft,
  ConnectionSession,
  DoctorResult,
  RestorePlan,
  ToolboxSession,
  WriteOptions,
} from "../model";

const API_ROOT = "/api/v1";
let sessionToken: string | undefined;

export class ToolboxApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly detail?: string;
  readonly correlationId?: string;

  constructor(status: number, payload: ApiErrorPayload) {
    super(payload.message || `Żądanie API zakończyło się kodem ${status}.`);
    this.name = "ToolboxApiError";
    this.status = status;
    this.code = payload.code;
    this.detail = payload.detail;
    this.correlationId = payload.correlation_id;
  }
}

interface WireConnectionDraft {
  host: string;
  username: string;
  password: string;
  ssl: boolean;
  verify_ssl: boolean;
  api_max_stage: CapabilityStage;
}

type WireConnectionSession = Partial<ConnectionSession> & {
  id: string;
  host: string;
  username: string;
  sessionToken?: string;
  session_token?: string;
  panorama_version?: string;
  api_max_stage?: CapabilityStage;
  connected_at?: string;
  candidate_dirty?: boolean;
  capability_warning?: string;
};

interface JsonOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
}

async function request<T>(path: string, options: JsonOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (sessionToken) headers.set("X-Toolbox-Session", sessionToken);

  const response = await fetch(`${API_ROOT}${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  const contentType = response.headers.get("content-type") ?? "";
  const payload: unknown = contentType.includes("application/json")
    ? await response.json()
    : { message: await response.text() };

  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? (payload as ApiErrorPayload) : {};
    throw new ToolboxApiError(response.status, error);
  }
  return payload as T;
}

async function download(path: string): Promise<Blob> {
  const headers = new Headers({ Accept: "application/octet-stream" });
  if (sessionToken) headers.set("X-Toolbox-Session", sessionToken);
  const response = await fetch(`${API_ROOT}${path}`, { headers, credentials: "same-origin" });
  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as ApiErrorPayload;
    throw new ToolboxApiError(response.status, payload);
  }
  return response.blob();
}

export const api = {
  async health(): Promise<{ status: string; version: string }> {
    return request("/health");
  },

  async doctor(connection?: Pick<ConnectionDraft, "host" | "ssl" | "verifySsl">): Promise<DoctorResult> {
    const host = connection?.host.trim();
    return request("/doctor", {
      method: "POST",
      body: connection && host
        ? { host, ssl: connection.ssl, verify_ssl: connection.verifySsl }
        : {},
    });
  },

  async connect(input: ConnectionDraft): Promise<ConnectionSession> {
    const body: WireConnectionDraft = {
      host: input.host,
      username: input.username,
      password: input.password,
      ssl: input.ssl,
      verify_ssl: input.verifySsl,
      api_max_stage: input.apiMaxStage,
    };
    const wire = await request<WireConnectionSession>("/connections", { method: "POST", body });
    sessionToken = wire.sessionToken ?? wire.session_token;
    const connection: ConnectionSession = {
      id: wire.id,
      host: wire.host,
      username: wire.username,
      panoramaVersion: wire.panoramaVersion ?? wire.panorama_version ?? "nieznana",
      apiMaxStage: wire.apiMaxStage ?? wire.api_max_stage ?? input.apiMaxStage,
      connectedAt: wire.connectedAt ?? wire.connected_at ?? new Date().toISOString(),
      candidateDirty: wire.candidateDirty ?? wire.candidate_dirty ?? false,
      capabilityWarning: wire.capabilityWarning ?? wire.capability_warning,
    };
    return connection;
  },

  async disconnect(): Promise<void> {
    try {
      await request("/connections/current", { method: "DELETE" });
    } finally {
      sessionToken = undefined;
    }
  },

  async createCleanupPlan(input: {
    connectionId: string;
    addresses: string[];
    runIcmp: boolean;
    recentHitDays: number;
  }): Promise<CleanupPlan> {
    return request("/cleanup/plans", {
      method: "POST",
      body: {
        connection_id: input.connectionId,
        addresses: input.addresses,
        run_icmp: input.runIcmp,
        recent_hit_days: input.recentHitDays,
      },
    });
  },

  async getCleanupPlan(planId: string): Promise<CleanupPlan> {
    return request(`/cleanup/plans/${encodeURIComponent(planId)}`);
  },

  async applyCandidate(sessionId: string, options: WriteOptions): Promise<ApiActionResult> {
    return request(`/sessions/${encodeURIComponent(sessionId)}/candidate`, {
      method: "POST",
      body: { enable_api_write: options.enableApiWrite },
    });
  },

  async commit(sessionId: string, options: WriteOptions): Promise<ApiActionResult> {
    return request(`/sessions/${encodeURIComponent(sessionId)}/commit`, {
      method: "POST",
      body: {
        enable_api_write: options.enableApiWrite,
        full: Boolean(options.allowFullCommit),
        allow_unisolated_commit: Boolean(options.allowUnisolatedCommit),
        allow_full_commit: Boolean(options.allowFullCommit),
      },
    });
  },

  async push(sessionId: string, deviceGroups: string[], options: WriteOptions): Promise<ApiActionResult> {
    return request(`/sessions/${encodeURIComponent(sessionId)}/push`, {
      method: "POST",
      body: {
        enable_api_write: options.enableApiWrite,
        device_groups: deviceGroups,
      },
    });
  },

  async audit(connectionId: string, addresses: string[]): Promise<AuditResult> {
    return request("/audits", {
      method: "POST",
      body: { connection_id: connectionId, addresses },
    });
  },

  async listSessions(): Promise<ToolboxSession[]> {
    return request("/sessions");
  },

  async getSession(sessionId: string): Promise<ToolboxSession> {
    return request(`/sessions/${encodeURIComponent(sessionId)}`);
  },

  async downloadSessionArtifact(sessionId: string, name: "commands" | "report" | "manifest" | "conflicts"): Promise<Blob> {
    return download(`/sessions/${encodeURIComponent(sessionId)}/artifacts/${name}`);
  },

  async createRestorePlan(input: {
    connectionId: string;
    ip?: string;
    sourceSessionId?: string;
  }): Promise<RestorePlan> {
    return request("/restore/plans", {
      method: "POST",
      body: {
        connection_id: input.connectionId,
        ip: input.ip || undefined,
        source_session_id: input.sourceSessionId || undefined,
      },
    });
  },

  async applyRestoreCandidate(planId: string, options: WriteOptions): Promise<ApiActionResult> {
    return request(`/restore/plans/${encodeURIComponent(planId)}/candidate`, {
      method: "POST",
      body: { enable_api_write: options.enableApiWrite },
    });
  },
};

export function clearApiSessionForTests(): void {
  sessionToken = undefined;
}
