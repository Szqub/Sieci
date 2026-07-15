import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, clearApiSessionForTests } from "../api/client";

describe("typed API client", () => {
  beforeEach(() => clearApiSessionForTests());
  afterEach(() => vi.restoreAllMocks());

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
    await api.applyCandidate("cleanup-1", { enableApiWrite: true });
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({ enable_api_write: true });
  });

  it("przekazuje osobną flagę full commit i oba jawne zezwolenia", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ message: "ok", session: {} }), { status: 200, headers: { "Content-Type": "application/json" } }));
    await api.commit("cleanup-1", {
      enableApiWrite: true,
      allowUnisolatedCommit: true,
      allowFullCommit: true,
    });
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      enable_api_write: true,
      full: true,
      allow_unisolated_commit: true,
      allow_full_commit: true,
    });
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
});
