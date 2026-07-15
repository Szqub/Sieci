import { fireEvent, render, screen } from "@testing-library/react";
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
    const writeToggle = await screen.findByRole("checkbox", { name: /włącz zapis przez api/i });
    expect(writeToggle).not.toBeChecked();
    fireEvent.click(writeToggle);
    expect(writeToggle).toBeChecked();

    expect(storageWrite).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
