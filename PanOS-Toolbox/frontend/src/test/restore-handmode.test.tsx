import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { demoRestorePlan } from "../demo";
import { RestorePage } from "../pages/RestorePage";

const baseProps = {
  query: "10.42.8.17",
  onQueryChange: vi.fn(),
  plan: demoRestorePlan,
  executionSession: null,
  executionJob: null,
  writeEnabled: false,
  connected: true,
  busy: null,
  error: null,
  onCreatePlan: vi.fn(),
  onApplyCandidate: vi.fn(),
  onCommit: vi.fn(),
  onPush: vi.fn(),
  onDownloadConflicts: vi.fn(),
  onViewArtifact: vi.fn(async (file: string) => `CLI ${file}`),
  onDownloadArtifact: vi.fn(),
  onOpenConnection: vi.fn(),
  onOpenWarnings: vi.fn(),
} as const;

describe("Restore Hand Mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn(async () => undefined) },
    });
  });

  it("pokazuje osobny bezpieczny zestaw Restore i rollback", () => {
    render(<RestorePage {...baseProps} />);
    expect(screen.getByText("Hand Mode — ręczne odtworzenie")).toBeInTheDocument();
    expect(screen.getByText("CLI READY")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Kopiuj wszystko" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Cofnięcie Restore" })).toBeEnabled();
  });

  it("wymaga dodatkowego potwierdzenia przed skopiowaniem konfliktów", async () => {
    render(<RestorePage {...baseProps} />);
    fireEvent.click(screen.getByRole("button", { name: "Kopiuj konflikty…" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("Kopiujesz konfliktowy Restore");
    expect(baseProps.onViewArtifact).not.toHaveBeenCalledWith("handmode_conflict_restore_commands.txt");
    fireEvent.click(screen.getByRole("button", { name: "Rozumiem — kopiuj konfliktowy Restore" }));
    await waitFor(() => expect(baseProps.onViewArtifact).toHaveBeenCalledWith("handmode_conflict_restore_commands.txt"));
  });

  it("blokuje kopiowanie, gdy renderer zwrócił pusty plik dla niepustego planu", () => {
    const blocked = {
      ...demoRestorePlan,
      artifacts: demoRestorePlan.artifacts.map((artifact) => artifact.file === "commands.txt" ? { ...artifact, sizeBytes: 0 } : artifact),
    };
    render(<RestorePage {...baseProps} plan={blocked} />);
    expect(screen.getByText("CLI BLOCK")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Kopiuj wszystko" })).toBeDisabled();
    expect(screen.getByText("Hand Mode Restore zablokowany")).toBeInTheDocument();
  });
});
