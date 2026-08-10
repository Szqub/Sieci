import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { demoCleanupPlan, demoSessions } from "../demo";
import { PlanPage } from "../pages/PlanPage";

const baseProps = {
  plan: demoCleanupPlan,
  executionJob: null,
  writeEnabled: true,
  busy: null,
  singlePlanBusy: null,
  error: null,
  onOpenCleanup: vi.fn(),
  onCreateSinglePlan: vi.fn(),
  onCreateSelectionPlan: vi.fn(),
  onExcludeTargets: vi.fn(),
  onExcludeComponents: vi.fn(),
  onUndoLastExclusion: vi.fn(),
  onPlanDependencies: vi.fn(),
  onRestoreTarget: vi.fn(),
  onApplyCandidate: vi.fn(),
  onPrepareCommitReview: vi.fn(),
  onCommit: vi.fn(),
  onPush: vi.fn(),
  onViewArtifact: vi.fn(async () => "preview"),
  onDownload: vi.fn(),
};

describe("staged execution gates", () => {
  it("pokazuje trzy osobne etapy bez selektora poziomu API", () => {
    render(<PlanPage {...baseProps} executionSession={null} />);
    expect(screen.getByRole("button", { name: "Zapisz Candidate przez API" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Commit" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Validate & Push" })).toBeDisabled();
    expect(screen.queryByText(/Tryb wykonania/)).not.toBeInTheDocument();
  });

  it("wydziela wskazany cel do osobnego planu", () => {
    const onCreateSinglePlan = vi.fn();
    render(<PlanPage {...baseProps} onCreateSinglePlan={onCreateSinglePlan} executionSession={null} />);
    const buttons = screen.getAllByRole("button", { name: "Tylko ten" });
    const enabled = buttons.find((button) => !button.hasAttribute("disabled"));
    expect(enabled).toBeDefined();
    fireEvent.click(enabled!);
    expect(onCreateSinglePlan).toHaveBeenCalledTimes(1);
  });

  it("wyklucza pojedynczy cel bez uruchamiania zapisu", () => {
    const onExcludeTargets = vi.fn();
    render(<PlanPage {...baseProps} onExcludeTargets={onExcludeTargets} executionSession={null} />);
    const buttons = screen.getAllByRole("button", { name: "Wyklucz" });
    const enabled = buttons.find((button) => !button.hasAttribute("disabled"));
    expect(enabled).toBeDefined();
    fireEvent.click(enabled!);
    expect(onExcludeTargets).toHaveBeenCalledTimes(1);
    expect(onExcludeTargets.mock.calls[0][0]).toHaveLength(1);
  });

  it("wyklucza zbiorczo zaznaczone cele", () => {
    const onExcludeTargets = vi.fn();
    render(<PlanPage {...baseProps} onExcludeTargets={onExcludeTargets} executionSession={null} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Zaznacz 10.42.16.19" }));
    fireEvent.click(screen.getByRole("button", { name: "Wyklucz zaznaczone" }));
    expect(onExcludeTargets).toHaveBeenCalledTimes(1);
    expect(onExcludeTargets.mock.calls[0][0][0].ip).toBe("10.42.16.19");
  });

  it("pozwala wykluczyć znalezioną politykę lub obiekt przez cały komponent", () => {
    const onExcludeComponents = vi.fn();
    render(<PlanPage {...baseProps} onExcludeComponents={onExcludeComponents} executionSession={null} />);
    fireEvent.click(screen.getByRole("button", { name: "Rozwiń 10.42.16.19" }));
    expect(screen.getAllByText("Allow-Legacy-API")).not.toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Wyklucz cały komponent" }));
    expect(onExcludeComponents).toHaveBeenCalledWith(["component-a"]);
  });

  it("blokuje Candidate, gdy po wykluczeniu nie zostały operacje", () => {
    render(<PlanPage {...baseProps} plan={{ ...demoCleanupPlan, operations: [], processCount: 0, excludedCount: 3 }} executionSession={null} />);
    expect(screen.getByRole("button", { name: "Zapisz Candidate przez API" })).toBeDisabled();
    expect(screen.getByText("Plan nie zawiera operacji")).toBeInTheDocument();
  });

  it("pokazuje wykluczone cele i pozwala wrócić do planu nadrzędnego", () => {
    const onUndoLastExclusion = vi.fn();
    const excludedPlan = {
      ...demoCleanupPlan,
      parentSessionId: "parent-session",
      excludedCount: 1,
      excludedTargets: ["10.42.16.19"],
      exclusionImpactedTargets: ["10.42.16.19"],
      addresses: demoCleanupPlan.addresses.map((target) => target.ip === "10.42.16.19"
        ? { ...target, decision: "excluded" as const, excludedByUser: true, exclusionReason: "Wykluczony ręcznie przez operatora." }
        : target),
    };
    render(<PlanPage {...baseProps} plan={excludedPlan} onUndoLastExclusion={onUndoLastExclusion} executionSession={null} />);
    expect(screen.getByText("1 cel poza wykonaniem")).toBeInTheDocument();
    expect(screen.getByText("Wykluczony z wykonania")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cofnij ostatnie wykluczenie" }));
    expect(onUndoLastExclusion).toHaveBeenCalledTimes(1);
  });

  it("po wykluczeniu jednego komponentu pozostawia pozostałe cele aktywne", () => {
    const onExcludeTargets = vi.fn();
    const excludedPlan = {
      ...demoCleanupPlan,
      parentSessionId: "parent-session",
      excludedCount: 1,
      excludedTargets: ["10.42.16.19"],
      exclusionImpactedTargets: ["10.42.16.19"],
      addresses: demoCleanupPlan.addresses.map((target) => target.ip === "10.42.16.19"
        ? { ...target, decision: "excluded" as const, excludedByUser: true }
        : target),
    };
    render(<PlanPage {...baseProps} plan={excludedPlan} onExcludeTargets={onExcludeTargets} executionSession={null} />);

    const remaining = screen.getByRole("checkbox", { name: "Zaznacz 10.42.16.21" });
    expect(remaining).toBeEnabled();
    fireEvent.click(remaining);
    fireEvent.click(screen.getByRole("button", { name: "Wyklucz zaznaczone" }));
    expect(onExcludeTargets).toHaveBeenCalledWith([
      expect.objectContaining({ ip: "10.42.16.21", decision: "process" }),
    ]);
  });

  it("pokazuje że przebudowa wykluczenia jest lokalna", () => {
    render(<PlanPage {...baseProps} singlePlanBusy="exclude:10.42.16.19" executionSession={null} />);
    expect(screen.getByText(/bez ponownego pobierania konfiguracji z Panoramy/i)).toBeInTheDocument();
  });

  it("nie pozwala ponowić candidate dla terminalnej sesji FAILED", () => {
    render(<PlanPage {...baseProps} executionSession={{ ...demoSessions[0], state: "FAILED" }} />);
    expect(screen.getByRole("button", { name: "Zapisz Candidate przez API" })).toBeDisabled();
  });

  it("wymaga osobnego ostrzeżenia przed commitem", () => {
    const onCommit = vi.fn();
    render(<PlanPage {...baseProps} executionSession={{ ...demoSessions[0], state: "PARTIAL" }} onCommit={onCommit} />);
    const commit = screen.getByRole("button", { name: "Commit" });
    expect(commit).toBeEnabled();
    fireEvent.click(commit);
    expect(screen.getByRole("dialog")).toHaveTextContent(/ostatni przegląd przed wysłaniem commit/i);
    expect(onCommit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /scope pass — wyślij commit/i }));
    expect(onCommit).toHaveBeenCalledTimes(1);
  });

  it("po live BLOCK pokazuje dokładny XPath i pozwala jawnie zaakceptować tylko jego fingerprint", () => {
    const onCommit = vi.fn();
    const digest = "b".repeat(64);
    const precommitGuard = {
      passed: false,
      findingCount: 1,
      outsidePlanCount: 1,
      checkedMutationCount: 6,
      candidateProjectionMatches: false,
      findingDigest: digest,
      overrideEligible: true,
      artifact: "precommit_scope_guard_demo.txt",
      findings: [{
        code: "CANDIDATE_PATH_OUTSIDE_PATCHSET",
        detail: "Candidate zawiera element, którego nie ma w projekcji PatchSet.",
        target: "running + PatchSet",
        ownerType: "policy",
        ownerName: "KEEP-THIS",
        scope: "DG-PROD",
        field: "source",
        xpath: "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DG-PROD']/pre-rulebase/security/rules/entry[@name='KEEP-THIS']/source",
        outsidePlan: true,
        differenceKind: "unexpected-in-candidate",
      }],
    };
    const failedSession = {
      ...demoSessions[0],
      state: "PARTIAL" as const,
      commitReview: demoCleanupPlan.commitReview,
      precommitGuard,
      artifacts: demoCleanupPlan.artifacts,
    };
    const executionJob = {
      id: "commit-failed",
      sessionId: failedSession.id,
      kind: "commit" as const,
      state: "failed" as const,
      progress: 28,
      message: "Etap commit został zatrzymany",
      items: [],
      session: failedSession,
      error: { code: "ConflictError", message: "Scope guard BLOCK" },
    };

    render(<PlanPage {...baseProps} executionSession={null} executionJob={executionJob} onCommit={onCommit} />);

    expect(screen.getByText(/live preflight bezpośrednio przed wysłaniem joba/i)).toBeInTheDocument();
    expect(screen.getAllByText(/KEEP-THIS.*source/).length).toBeGreaterThan(0);
    expect(screen.getByText(/XPath: \/config\/devices/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Commit" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /ignoruj tę blokadę/i }));
    expect(screen.getByRole("dialog")).toHaveTextContent(/jawny override scope guard/i);
    const acknowledgement = screen.getByRole("checkbox", { name: /rozumiem, że ignoruję dokładnie/i });
    fireEvent.click(acknowledgement);
    fireEvent.click(screen.getByRole("button", { name: /ignoruj dokładnie tę blokadę i uruchom commit/i }));
    expect(onCommit).toHaveBeenCalledWith(digest);
  });
});
