import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { demoCleanupPlan, demoSessions } from "../demo";
import { PlanPage } from "../pages/PlanPage";

const baseProps = {
  plan: demoCleanupPlan,
  apiMaxStage: "push" as const,
  writeEnabled: true,
  busy: null,
  error: null,
  onOpenCleanup: vi.fn(),
  onApplyCandidate: vi.fn(),
  onCommit: vi.fn(),
  onPush: vi.fn(),
  onDownload: vi.fn(),
};

describe("staged execution gates", () => {
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
