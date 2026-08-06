import { describe, expect, it } from "vitest";
import { stageAllows } from "../model";
import { parseAddressInput, parseNameInput, pluralize } from "../utils";

describe("parseAddressInput", () => {
  it("deduplikuje adresy i ignoruje komentarze", () => {
    const parsed = parseAddressInput("# paczka A\n10.0.0.1\n10.0.0.2, 10.0.0.1 # duplikat\n\n");
    expect(parsed.addresses).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(parsed.duplicates).toBe(1);
    expect(parsed.ignored).toBe(1);
  });

  it("zachowuje kolejność wejścia", () => {
    expect(parseAddressInput("2001:db8::2;2001:db8::1").addresses).toEqual(["2001:db8::2", "2001:db8::1"]);
  });
});

describe("parseNameInput", () => {
  it("zachowuje spacje w nazwach i deduplikuje całe wiersze", () => {
    const parsed = parseNameInput("# policies\nALLOW LEGACY APP\nALLOW LEGACY APP\nOLD-NAT");
    expect(parsed.names).toEqual(["ALLOW LEGACY APP", "OLD-NAT"]);
    expect(parsed.duplicates).toBe(1);
    expect(parsed.ignored).toBe(1);
  });
});

describe("capability gates", () => {
  it("nie pozwala profilowi candidate wykonać commit lub push", () => {
    expect(stageAllows("candidate", "read-only")).toBe(true);
    expect(stageAllows("candidate", "candidate")).toBe(true);
    expect(stageAllows("candidate", "commit")).toBe(false);
    expect(stageAllows("candidate", "push")).toBe(false);
  });

  it("odmienia polskie etykiety liczbowe", () => {
    const forms: [string, string, string] = ["adres", "adresy", "adresów"];
    expect(pluralize(1, forms)).toBe("adres");
    expect(pluralize(3, forms)).toBe("adresy");
    expect(pluralize(12, forms)).toBe("adresów");
  });
});
