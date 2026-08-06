import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";

describe("runtime safety state", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("nie utrwala write toggle ani sekretów w Web Storage", async () => {
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /dane demonstracyjne/i }));
    const writeToggle = await screen.findByRole("checkbox", { name: /przełącz read only \/ write/i });
    await waitFor(() => expect(writeToggle).toBeEnabled());
    expect(writeToggle).not.toBeChecked();
    fireEvent.click(writeToggle);
    expect(await screen.findByRole("dialog")).toHaveTextContent(/czy na pewno chcesz włączyć write/i);
    expect(writeToggle).not.toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: /tak, włącz write/i }));
    expect(writeToggle).toBeChecked();

    expect(storageWrite).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
