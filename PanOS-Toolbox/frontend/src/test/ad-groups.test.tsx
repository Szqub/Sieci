import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AdGroupsPage, type AdGroupDraft } from "../pages/AdGroupsPage";
import type { AdGroupGenerationResult } from "../model";

const draft: AdGroupDraft = {
  groupsText: "GG-VPN\nGG-ADMINS",
  outputName: "VPN_USERS",
  mappingName: "LDAP_GM1",
  vsys: "vsys1",
  templateName: "TPL-NET",
};

const result: AdGroupGenerationResult = {
  generatedAt: "2026-08-06T10:00:00Z",
  outputGroupName: "AD__VPN_USERS",
  mappingName: "LDAP_GM1",
  vsys: "vsys1",
  templateName: "TPL-NET",
  panoramaPath: "Device Templates > TPL-NET > User Identification > LDAP_GM1 > Custom Group > vsys1",
  chunkSize: 6,
  inputCount: 2,
  validCount: 1,
  skippedCount: 1,
  groups: [
    { name: "GG-VPN", status: "valid", memberCount: 3, distinguishedName: "CN=GG-VPN,DC=example", detail: "Grupa istnieje i ma 3 członków." },
    { name: "GG-ADMINS", status: "empty", memberCount: 0, detail: "Grupa istnieje, ale nie ma żadnego członka — pominięto." },
  ],
  blocks: [{ index: 1, filter: "(memberof=CN=GG-VPN,DC=example)", sourceGroups: ["GG-VPN"] }],
  clipboardText: "(memberof=CN=GG-VPN,DC=example)",
  cliGroups: [{ index: 1, filter: "(memberof=CN=GG-VPN,DC=example)", sourceGroups: ["GG-VPN"], panoramaGroupName: "AD__VPN_USERS", cliCommand: "set template \"TPL-NET\" config vsys \"vsys1\" group-mapping \"LDAP_GM1\" custom-group \"AD__VPN_USERS\" ldap-filter \"(memberof=CN=GG-VPN,DC=example)\"", rollbackCliCommand: "delete template \"TPL-NET\" config vsys \"vsys1\" group-mapping \"LDAP_GM1\" custom-group \"AD__VPN_USERS\"" }],
  cliText: "set template \"TPL-NET\" config vsys \"vsys1\" group-mapping \"LDAP_GM1\" custom-group \"AD__VPN_USERS\" ldap-filter \"(memberof=CN=GG-VPN,DC=example)\"\n",
  rollbackCliText: "delete template \"TPL-NET\" config vsys \"vsys1\" group-mapping \"LDAP_GM1\" custom-group \"AD__VPN_USERS\"\n",
  handModeReady: true,
  warnings: ["Pusta grupa"],
};

describe("AD group generator", () => {
  it("uruchamia walidację dla wypełnionego formularza", () => {
    const onGenerate = vi.fn();
    render(<AdGroupsPage draft={draft} onDraftChange={vi.fn()} result={null} busy={false} error={null} onGenerate={onGenerate} />);
    fireEvent.click(screen.getByRole("button", { name: "Sprawdź AD i wygeneruj" }));
    expect(onGenerate).toHaveBeenCalledTimes(1);
    expect(screen.getByText("AD__")).toBeInTheDocument();
  });

  it("pokazuje walidację i gotowy filtr", () => {
    render(<AdGroupsPage draft={draft} onDraftChange={vi.fn()} result={result} busy={false} error={null} onGenerate={vi.fn()} />);
    expect(screen.getAllByText("AD__VPN_USERS").length).toBeGreaterThan(0);
    expect(screen.getByText("Poprawna")).toBeInTheDocument();
    expect(screen.getByText("Pusta")).toBeInTheDocument();
    expect(screen.getByText("(memberof=CN=GG-VPN,DC=example)")).toBeInTheDocument();
    expect(screen.getByText("Hand Mode — Custom LDAP Group CLI")).toBeInTheDocument();
    expect(screen.getByText(/set template/)).toBeInTheDocument();
  });
});
