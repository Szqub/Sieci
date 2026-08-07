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
});
