import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ExecutionProgress } from "../components/ExecutionProgress";
import type { ExecutionJob } from "../model";

const runningCommit: ExecutionJob = {
  id: "commit-test",
  sessionId: "session-test",
  kind: "commit",
  state: "running",
  progress: 46,
  message: "Commit job 88: ACT · Panorama nie podała procentu",
  current: {
    event: "panorama-job-poll",
    message: "Commit job 88: ACT",
    progress: 46,
    jobId: "88",
    status: "ACT",
    pollCount: 3,
    elapsedSeconds: 6.2,
  },
  items: [],
};

describe("ExecutionProgress", () => {
  it("shows active polling instead of a misleading frozen percentage", () => {
    render(<ExecutionProgress job={runningCommit} />);
    expect(screen.getByText(/Panorama nie raportuje procentu/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "46");
    expect(screen.getByText("6.2 s")).toBeInTheDocument();
  });

  it("renders a terminal job at 100 percent", () => {
    render(<ExecutionProgress job={{ ...runningCommit, state: "success", progress: 100, message: "Commit zakończony poprawnie" }} />);
    expect(screen.getByText("100%")).toBeInTheDocument();
    expect(screen.getByText("success")).toBeInTheDocument();
  });

  it("distinguishes a long Panorama job from a frozen frontend", () => {
    render(<ExecutionProgress job={{
      ...runningCommit,
      current: {
        ...runningCommit.current!,
        elapsedSeconds: 721,
        pollCount: 361,
        queued: "YES",
        positionInQueue: 2,
        lastResponseAt: "2026-08-10T10:00:00Z",
        longRunning: true,
        warnings: "Commit waits for another job.",
      },
    }} />);
    expect(screen.getByText("Job czeka w kolejce Panoramy")).toBeInTheDocument();
    expect(screen.getByText(/Panorama odpowiada · poll 361/)).toBeInTheDocument();
    expect(screen.getByText(/Pozycja w kolejce: 2/)).toBeInTheDocument();
    expect(screen.getByText("Commit waits for another job.")).toBeInTheDocument();
  });
});
