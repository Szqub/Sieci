import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, clearApiSessionForTests, setAppTokenForTests } from "../api/client";

describe("typed API client", () => {
  beforeEach(() => {
    clearApiSessionForTests();
    setAppTokenForTests("test-app-token");
  });
  afterEach(() => vi.restoreAllMocks());

  it("czyta lokalny indeks historii bez tokenu Panorama", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ generatedAt: "2026-08-10T10:00:00Z", storage: "C:\\Users\\test\\Documents\\PanOS Toolbox\\sessions", sessionCount: 0, mutationCount: 0, issues: [], sessions: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.history();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/history");
    const headers = new Headers((fetchMock.mock.calls[0][1] as RequestInit).headers);
    expect(headers.get("X-Toolbox-Session")).toBeNull();
    expect(headers.get("X-Toolbox-App-Token")).toBe("test-app-token");
  });

  it("trzyma token sesji wyłącznie w pamięci modułu", async () => {
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: "conn-1",
        sessionToken: "short-lived-token",
        host: "panorama.local",
        username: "admin",
        panoramaVersion: "10.2.16-h4",
        apiMaxStage: "read-only",
        connectedAt: "2026-07-15T10:00:00Z",
        candidateDirty: false,
      }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } }));

    await api.connect({ host: "panorama.local", username: "admin", password: "secret", ssl: true, verifySsl: false, apiMaxStage: "read-only" });
    await api.listSessions();

    const secondRequest = fetchMock.mock.calls[1][1] as RequestInit;
    expect(new Headers(secondRequest.headers).get("X-Toolbox-Session")).toBe("short-lived-token");
    expect(storageWrite).not.toHaveBeenCalled();
  });

  it("wysyła runtime write gate przy mutacji candidate", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ message: "ok", session: {} }), { status: 200, headers: { "Content-Type": "application/json" } }));
    await api.applyCandidate("cleanup-1", { enableApiWrite: true, executionStage: "candidate" });
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      enable_api_write: true,
      execution_stage: "candidate",
    });
  });

  it("przekazuje osobną flagę full commit i oba jawne zezwolenia", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ message: "ok", session: {} }), { status: 200, headers: { "Content-Type": "application/json" } }));
    await api.commit("cleanup-1", {
      enableApiWrite: true,
      executionStage: "commit",
      allowUnisolatedCommit: true,
      allowFullCommit: true,
    });
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      enable_api_write: true,
      execution_stage: "commit",
      full: true,
      allow_unisolated_commit: true,
      allow_full_commit: true,
      allow_scope_guard_override: false,
    });
  });

  it("uruchamia commit i push jako joby w tle", async () => {
    const response = () => new Response(JSON.stringify({ id: "job-1", state: "queued", progress: 0, items: [] }), { status: 202, headers: { "Content-Type": "application/json" } });
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(response())
      .mockResolvedValueOnce(response());

    await api.startCommitJob("cleanup-1", {
      enableApiWrite: true,
      executionStage: "push",
      allowUnisolatedCommit: true,
      allowScopeGuardOverride: true,
      acknowledgedScopeGuardDigest: "a".repeat(64),
    });
    await api.startPushJob("cleanup-1", ["DG-A"], { enableApiWrite: true, executionStage: "push" });

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/sessions/cleanup-1/commit-jobs");
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string)).toMatchObject({
      allow_scope_guard_override: true,
      acknowledged_scope_guard_digest: "a".repeat(64),
    });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/sessions/cleanup-1/push-jobs");
    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string)).toMatchObject({ device_groups: ["DG-A"] });
  });

  it("uruchamia lokalny Doctor bez hosta Panorama", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true, checks: [], generatedAt: "2026-07-15T10:00:00Z" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.doctor({ host: "   ", ssl: true, verifySsl: true });

    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({});
  });

  it("wysyła grupy AD i metadane miejsca docelowego bez sesji Panorama", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ outputGroupName: "AD__VPN", groups: [], blocks: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.generateAdGroup({
      groups: ["GG-VPN", "GG-ADMINS"],
      outputName: "VPN",
      mappingName: "LDAP_GM1",
      vsys: "vsys1",
      templateName: "TPL-NET",
    });

    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      groups: ["GG-VPN", "GG-ADMINS"],
      output_name: "VPN",
      mapping_name: "LDAP_GM1",
      vsys: "vsys1",
      template_name: "TPL-NET",
    });
    expect(new Headers(request.headers).get("X-Toolbox-Session")).toBeNull();
  });

  it("wysyła cztery niezależne listy celów cleanup", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "p", addresses: [], operations: [] }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await api.createCleanupPlan({
      connectionId: "conn",
      addresses: ["192.0.2.1"],
      addressObjects: ["OLD OBJECT"],
      addressGroups: ["OLD-GROUP"],
      policies: ["ALLOW OLD"],
      runIcmp: false,
      recentHitDays: 30,
    });
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toMatchObject({
      addresses: ["192.0.2.1"],
      address_objects: ["OLD OBJECT"],
      address_groups: ["OLD-GROUP"],
      policies: ["ALLOW OLD"],
    });
  });

  it("tworzy bezpieczny plan wykluczeń dla wskazanych celów", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "child", addresses: [], operations: [] }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.createExclusionPlan("session parent/1", ["policy:KEEP-ME", "object:KEEP-IP"]);

    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/cleanup/plans/session%20parent%2F1/exclusions",
    );
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      targets: ["policy:KEEP-ME", "object:KEEP-IP"],
      component_ids: [],
    });
  });

  it("wyklucza dokładny atomowy komponent z inspektora operacji", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "child", addresses: [], operations: [] }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.createExclusionPlan("session-1", [], ["component-policy-1"]);

    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      targets: [],
      component_ids: ["component-policy-1"],
    });
  });
});
