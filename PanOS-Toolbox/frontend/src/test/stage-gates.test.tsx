import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { demoCleanupPlan, demoSessions } from "../demo";
import { PlanPage } from "../pages/PlanPage";

const baseProps = {
  plan: demoCleanupPlan,
  executionStage: "push" as const,
  onExecutionStageChange: vi.fn(),
  writeEnabled: true,
  busy: null,
  singlePlanBusy: null,
  error: null,
  onOpenCleanup: vi.fn(),
  onCreateSinglePlan: vi.fn(),
  onApplyCandidate: vi.fn(),
  onCommit: vi.fn(),
  onPush: vi.fn(),
  onDownload: vi.fn(),
};

describe("staged execution gates", () => {
  it("pozwala wybrać runtime stage niezależnie od profilu połączenia", () => {
    const onExecutionStageChange = vi.fn();
    render(<PlanPage {...baseProps} executionStage="candidate" onExecutionStageChange={onExecutionStageChange} executionSession={null} />);
    fireEvent.click(screen.getByRole("button", { name: "Tryb wykonania commit" }));
    expect(onExecutionStageChange).toHaveBeenCalledWith("commit");
  });

  it("wydziela wskazany cel do osobnego planu", () => {
    const onCreateSinglePlan = vi.fn();
    render(<PlanPage {...baseProps} onCreateSinglePlan={onCreateSinglePlan} executionSession={null} />);
    const buttons = screen.getAllByRole("button", { name: "Osobny plan" });
    const enabled = buttons.find((button) => !button.hasAttribute("disabled"));
    expect(enabled).toBeDefined();
    fireEvent.click(enabled!);
    expect(onCreateSinglePlan).toHaveBeenCalledTimes(1);
  });

  it("nie pozwala ponowić candidate dla terminalnej sesji FAILED", () => {
    render(<PlanPage {...baseProps} executionSession={{ ...demoSessions[0], state: "FAILED" }} />);
    expect(screen.getByRole("button", { name: "Zapisz i zwaliduj Candidate" })).toBeDisabled();
  });

  it("pozwala commitować PARTIAL dopiero po jawnej zgodzie Unisolated", () => {
    const onCommit = vi.fn();
    render(<PlanPage {...baseProps} executionSession={{ ...demoSessions[0], state: "PARTIAL" }} onCommit={onCommit} />);
    const commit = screen.getByRole("button", { name: "Uruchom partial commit" });
    expect(commit).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox", { name: /Pozwól na nieizolowany partial commit/ }));
    expect(commit).toBeEnabled();
    fireEvent.click(commit);
    expect(onCommit).toHaveBeenCalledWith(true, false);
  });
});
