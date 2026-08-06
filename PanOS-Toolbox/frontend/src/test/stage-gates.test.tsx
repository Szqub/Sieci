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
  onPlanDependencies: vi.fn(),
  onRestoreTarget: vi.fn(),
  onApplyCandidate: vi.fn(),
  onCommit: vi.fn(),
  onPush: vi.fn(),
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
    expect(screen.getByRole("dialog")).toHaveTextContent(/potwierdź commit/i);
    expect(onCommit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /tak, uruchom commit/i }));
    expect(onCommit).toHaveBeenCalledTimes(1);
  });
});
