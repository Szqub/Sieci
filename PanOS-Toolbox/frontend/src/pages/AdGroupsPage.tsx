import { useMemo, useRef, useState } from "react";
import { CheckCircle2, Clipboard, Copy, FileUp, FolderTree, ShieldCheck, UsersRound, XCircle } from "lucide-react";
import type { AdGroupGenerationResult, AdGroupStatus } from "../model";
import { parseNameInput, pluralize } from "../utils";
import { Button, Callout, Card, CardHeader, PageHeader, StatCard, StatusPill } from "../components/Primitives";

export interface AdGroupDraft {
  groupsText: string;
  outputName: string;
  mappingName: string;
  vsys: string;
  templateName: string;
}

interface AdGroupsPageProps {
  draft: AdGroupDraft;
  onDraftChange: (draft: AdGroupDraft) => void;
  result: AdGroupGenerationResult | null;
  busy: boolean;
  error: string | null;
  onGenerate: () => void;
}

const statusLabels: Record<AdGroupStatus, string> = {
  valid: "Poprawna",
  empty: "Pusta",
  "not-found": "Nie istnieje",
  error: "Błąd odczytu",
};

const statusTones: Record<AdGroupStatus, "success" | "warning" | "danger"> = {
  valid: "success",
  empty: "warning",
  "not-found": "danger",
  error: "danger",
};

export function AdGroupsPage({ draft, onDraftChange, result, busy, error, onGenerate }: AdGroupsPageProps) {
  const parsed = useMemo(() => parseNameInput(draft.groupsText), [draft.groupsText]);
  const [copied, setCopied] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const update = <K extends keyof AdGroupDraft>(key: K, value: AdGroupDraft[K]) => onDraftChange({ ...draft, [key]: value });

  const copy = async (key: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(key);
    window.setTimeout(() => setCopied((current) => current === key ? null : current), 1600);
  };

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Workflow / Add / Active Directory"
        title="Generator Custom LDAP Group"
        description="Sprawdź istniejące grupy AD, odrzuć brakujące lub puste i wygeneruj filtry memberof gotowe do wklejenia w Panorama."
      />

      <Callout severity="info" title="Generator nie zmienia AD ani Panoramy">
        <p>Walidacja jest wykonywana lokalnie przez PowerShell i moduł ActiveDirectory (RSAT). Wynik to bezpieczny blok do ręcznego wklejenia; żadne API write nie jest uruchamiane.</p>
      </Callout>
      {error && <Callout severity="danger" title="Nie udało się wygenerować grupy"><p>{error}</p></Callout>}

      <div className="ad-group-layout">
        <Card className="ad-group-input-card">
          <CardHeader title="Grupy źródłowe w AD" description="Jedna nazwa w wierszu; duże listy można wkleić bezpośrednio." action={<UsersRound size={21} />} />
          <div className="address-editor-wrap ad-group-editor">
            <div className="address-editor__toolbar">
              <div><span className="editor-count">{parsed.names.length}</span><span>{pluralize(parsed.names.length, ["grupa", "grupy", "grup"])}</span></div>
              <div>
                <button type="button" onClick={() => fileInput.current?.click()}><FileUp size={14} /> Wczytaj plik TXT</button>
                <span>maks. 500</span>
              </div>
              <input
                ref={fileInput}
                className="visually-hidden"
                type="file"
                accept=".txt,text/plain"
                aria-label="Wczytaj nazwy grup z pliku tekstowego"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) void file.text().then((value) => update("groupsText", value));
                  event.target.value = "";
                }}
              />
            </div>
            <textarea
              className="address-editor"
              value={draft.groupsText}
              onChange={(event) => update("groupsText", event.target.value)}
              placeholder={"GG_NET_VPN_USERS\nGG_NET_ADMINISTRATORS\nGG_APP_FINANCE"}
              spellCheck={false}
              aria-label="Nazwy grup Active Directory"
            />
            <p className="editor-hint">Toolbox wywoła Get-ADGroup dla każdej unikalnej nazwy oraz sprawdzi właściwość Members.</p>
            <div className="address-editor__footer">
              <span>Duplikaty: <strong>{parsed.duplicates}</strong></span>
              <span>Komentarze: <strong>{parsed.ignored}</strong></span>
              <button type="button" onClick={() => update("groupsText", "")} disabled={!draft.groupsText}>Wyczyść</button>
            </div>
          </div>
        </Card>

        <div className="ad-group-settings">
          <Card>
            <CardHeader title="Grupa wynikowa w Panorama" description="Prefiks AD__ zostanie dodany automatycznie, jeśli go nie wpiszesz." action={<FolderTree size={20} />} />
            <div className="form-stack">
              <label className="field">
                <span>Nazwa głównej grupy</span>
                <div className="ad-prefix-input"><strong>AD__</strong><input value={draft.outputName.replace(/^AD__/i, "")} onChange={(event) => update("outputName", event.target.value)} placeholder="VPN_USERS" spellCheck={false} /></div>
              </label>
              <div className="field-grid field-grid--2">
                <label className="field"><span>Group Mapping</span><div className="input-with-icon"><FolderTree size={16} /><input value={draft.mappingName} onChange={(event) => update("mappingName", event.target.value)} placeholder="LDAP_GM1" spellCheck={false} /></div></label>
                <label className="field"><span>VSYS</span><div className="input-with-icon"><ShieldCheck size={16} /><input value={draft.vsys} onChange={(event) => update("vsys", event.target.value)} placeholder="vsys1" spellCheck={false} /></div></label>
              </div>
              <label className="field"><span>Device Template <small>opcjonalnie, informacyjnie</small></span><div className="input-with-icon"><FolderTree size={16} /><input value={draft.templateName} onChange={(event) => update("templateName", event.target.value)} placeholder="np. TEMPLATE-NET" spellCheck={false} /></div></label>
              <Button variant="primary" onClick={onGenerate} loading={busy} disabled={parsed.names.length === 0 || !draft.outputName.trim() || !draft.mappingName.trim() || !draft.vsys.trim()} icon={<UsersRound size={18} />}>Sprawdź AD i wygeneruj</Button>
            </div>
          </Card>
          <Callout severity="warning" title="Wymagane RSAT"><p>Jeśli moduł ActiveDirectory nie jest dostępny, Toolbox pokaże błąd zależności. Nie próbuje samodzielnie niczego instalować.</p></Callout>
        </div>
      </div>

      {result && (
        <>
          <div className="analysis-preview">
            <StatCard label="Wejście" value={result.inputCount} detail="unikalne grupy AD" />
            <StatCard label="Poprawne" value={result.validCount} detail="istnieją i mają członków" tone="success" />
            <StatCard label="Pominięte" value={result.skippedCount} detail="puste, brakujące lub błąd" tone={result.skippedCount ? "warning" : "neutral"} />
          </div>

          <Card className="ad-result-card">
            <CardHeader title={result.outputGroupName} description={result.panoramaPath} action={<div className="ad-result-actions"><Button onClick={() => void copy("name", result.outputGroupName)} icon={<Copy size={15} />}>{copied === "name" ? "Skopiowano" : "Kopiuj nazwę"}</Button><StatusPill tone={result.blocks.length ? "success" : "warning"}>{result.blocks.length} bloków</StatusPill></div>} />
            <div className="ad-validation-list">
              {result.groups.map((group) => (
                <div key={group.name} className={`ad-validation-row ad-validation-row--${group.status}`}>
                  {group.status === "valid" ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
                  <div><strong>{group.name}</strong><span>{group.detail}</span>{group.distinguishedName && <code>{group.distinguishedName}</code>}</div>
                  <StatusPill tone={statusTones[group.status]} dot={false}>{statusLabels[group.status]}</StatusPill>
                </div>
              ))}
            </div>
          </Card>

          {result.blocks.length > 0 ? (
            <Card className="ad-filter-card">
              <CardHeader title="Bloki LDAP do wklejenia" description={`Każdy blok zawiera maksymalnie ${result.chunkSize} grup źródłowych.`} action={<Button onClick={() => void copy("all", result.clipboardText)} icon={<Clipboard size={16} />}>{copied === "all" ? "Skopiowano" : "Kopiuj wszystko"}</Button>} />
              <div className="ad-filter-list">
                {result.blocks.map((block) => (
                  <div className="ad-filter-block" key={block.index}>
                    <div><strong>Blok {block.index}</strong><span>{block.sourceGroups.join(" · ")}</span><button type="button" onClick={() => void copy(`block-${block.index}`, block.filter)} aria-label={`Kopiuj blok ${block.index}`}><Copy size={15} />{copied === `block-${block.index}` ? "Skopiowano" : "Kopiuj"}</button></div>
                    <pre>{block.filter}</pre>
                  </div>
                ))}
              </div>
            </Card>
          ) : <Callout severity="danger" title="Brak bloku do wklejenia"><p>Żadna z podanych grup nie przeszła walidacji istnienia i co najmniej jednego członka.</p></Callout>}
        </>
      )}
    </div>
  );
}
