import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ToolboxSession } from "../model";
import { HistoryPage } from "../pages/HistoryPage";

const session: ToolboxSession = {
  id: "session-20260810T100000Z-deadbeef",
  kind: "cleanup",
  state: "PUSHED",
  createdAt: "2026-08-10T10:00:00Z",
  updatedAt: "2026-08-10T10:05:00Z",
  operator: "netops",
  panoramaHost: "panorama.local",
  itemCount: 1,
  targets: ["policy:ALLOW-LEGACY"],
  backupCount: 1,
  backupItems: [{ mutationId: "mutation-1", entityType: "policy", entityName: "shared/pre-rulebase/security/ALLOW-LEGACY", file: "entities/ALLOW-LEGACY.xml", sha256: "abc", targets: ["policy:ALLOW-LEGACY"], componentId: "component-1" }],
  canRestore: true,
  affectedDeviceGroups: ["DG-PROD"],
  description: "Cleanup Panorama",
  jobs: [],
  artifacts: [{ file: "entities/ALLOW-LEGACY.xml", kind: "entity-backup:policy", contentType: "application/xml", sizeBytes: 512, viewable: true, downloadable: true }],
  timeline: [{ sequence: 1, timestamp: "2026-08-10T10:00:00Z", eventType: "SESSION_CREATED", label: "Utworzono plan i backup" }, { sequence: 2, timestamp: "2026-08-10T10:05:00Z", eventType: "STATE_CHANGED", state: "PUSHED", label: "Zmiana stanu sesji" }],
  historyItems: [{
    id: "session:mutation-1",
    mutationId: "mutation-1",
    componentId: "component-1",
    entityType: "policy",
    entityName: "ALLOW-LEGACY",
    entityKey: "shared/pre-rulebase/security/ALLOW-LEGACY",
    scope: "DG-PROD",
    rulebase: "pre-rulebase",
    policyType: "security",
    xpath: "/config/devices/entry/device-group/entry[@name='DG-PROD']/pre-rulebase/security/rules/entry[@name='ALLOW-LEGACY']",
    targets: ["policy:ALLOW-LEGACY", "10.42.16.19"],
    operations: [{ direction: "forward", action: "delete", xpath: "/config/example" }, { direction: "inverse", action: "set", xpath: "/config/example" }],
    backupFile: "entities/ALLOW-LEGACY.xml",
    plannedAt: "2026-08-10T10:00:00Z",
    appliedAt: "2026-08-10T10:01:00Z",
    committedAt: "2026-08-10T10:03:00Z",
    pushedAt: "2026-08-10T10:05:00Z",
    effectiveAt: "2026-08-10T10:05:00Z",
    executionStatus: "pushed",
    wasApplied: true,
    canQuickRestore: true,
    restoreTargets: ["policy:ALLOW-LEGACY"],
    searchValues: ["ALLOW-LEGACY", "10.42.16.19", "DG-PROD"],
  }],
};

const baseProps = {
  sessions: [session],
  selected: session,
  storage: "C:\\Users\\Firell\\Documents\\PanOS Toolbox\\sessions",
  issues: [],
  connected: false,
  busy: false,
  error: null,
  onRefresh: vi.fn(),
  onSelect: vi.fn(),
  onRestore: vi.fn(),
  onRestoreTargets: vi.fn(),
  onDownloadBundle: vi.fn(),
  onViewArtifact: vi.fn(async () => "<entry name=\"ALLOW-LEGACY\" />"),
  onDownloadArtifact: vi.fn(),
  onReconcileExternal: vi.fn(),
};

describe("offline session history", () => {
  it("wyszukuje po IP wewnątrz indeksu mutacji i przygotowuje szybki Restore", () => {
    const onRestoreTargets = vi.fn();
    render(<HistoryPage {...baseProps} onRestoreTargets={onRestoreTargets} />);

    expect(screen.getByText("Pełny odczyt historii działa offline")).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText(/IP, polityka, obiekt/i), { target: { value: "10.42.16.19" } });
    expect(screen.getAllByText("ALLOW-LEGACY").length).toBeGreaterThan(0);
    expect(screen.getByText("push wykonany")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Przygotuj Restore" }));
    expect(onRestoreTargets).toHaveBeenCalledWith(["policy:ALLOW-LEGACY"]);
  });

  it("wyświetla konkretny backup bez połączenia z Panorama", async () => {
    render(<HistoryPage {...baseProps} />);
    fireEvent.click(screen.getByRole("button", { name: "Wyświetl backup" }));
    expect(await screen.findByText(/<entry name="ALLOW-LEGACY"/)).toBeInTheDocument();
    expect(baseProps.onViewArtifact).toHaveBeenCalledWith(session.id, "entities/ALLOW-LEGACY.xml");
  });
});
