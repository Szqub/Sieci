import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  ChevronDown,
  ChevronRight,
  FileText,
  Gauge,
  ListTree,
  LoaderCircle,
  Network,
  Radar,
  Search,
  ShieldCheck,
  Upload,
  Workflow,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import type { AnalysisJob, ConnectionSession, LookupEntity, LookupKind, LookupResult } from "../model";
import { formatDate } from "../model";
import { parseAddressInput, parseNameInput, pluralize } from "../utils";
import { Button, Callout, Card, CardHeader, PageHeader, ProgressBar, StatCard, StatusPill, Toggle } from "../components/Primitives";

interface CleanupPageProps {
  connection: ConnectionSession | null;
  targetTexts: Record<TargetKind, string>;
  onTargetTextChange: (kind: TargetKind, value: string) => void;
  runIcmp: boolean;
  onRunIcmpChange: (value: boolean) => void;
  recentHitDays: number;
  onRecentHitDaysChange: (value: number) => void;
  busy: boolean;
  progress: AnalysisJob | null;
  lookupResult: LookupResult | null;
  lookupBusy: boolean;
  error: string | null;
  onLookup: (kind: LookupKind, names: string[], deviceGroup?: string) => void;
  onAddLookupEntities: (entities: LookupEntity[]) => void;
  onAnalyze: () => void;
  onOpenConnection: () => void;
}

type TargetKind = "ip" | "object" | "group" | "policy";
type WorkMode = "point" | "batch";

const targetOptions: Record<TargetKind, { label: string; hint: string; placeholder: string }> = {
  ip: { label: "IP / literal", hint: "Adresy IP; można rozdzielać spacją, przecinkiem lub nową linią.", placeholder: "10.20.30.41\n10.20.30.42\n# wycofane serwery" },
  object: { label: "Obiekty", hint: "Dokładna nazwa obiektu adresowego w każdym wierszu.", placeholder: "OLD-WEB-SERVER\nOLD-DATABASE" },
  group: { label: "Grupy", hint: "Dokładna nazwa statycznej address group w każdym wierszu.", placeholder: "GRP-LEGACY-SERVERS\nGRP-OLD-DMZ" },
  policy: { label: "Polityki", hint: "Dokładna nazwa polityki w każdym wierszu; spacje są zachowywane.", placeholder: "ALLOW LEGACY APP\nOLD-NAT-RULE" },
};

const lookupOptions: Array<{ id: LookupKind; label: string }> = [
  { id: "address", label: "Obiekt" },
  { id: "address-group", label: "Grupa" },
  { id: "policy", label: "Polityka" },
  { id: "ip", label: "IP" },
];

function lastHitClass(item: Pick<LookupEntity, "lastHit" | "lastHitAgeDays" | "hitCount">): string {
  if (!item.lastHit || item.hitCount === 0) return "last-hit last-hit--green";
  const age = item.lastHitAgeDays ?? Math.max(0, (Date.now() - new Date(item.lastHit).getTime()) / 86_400_000);
  if (age >= 183) return "last-hit last-hit--green";
  if (age >= 30) return "last-hit last-hit--yellow";
  if (age >= 14) return "last-hit last-hit--orange";
  return "last-hit last-hit--red";
}

export function CleanupPage({ connection, targetTexts, onTargetTextChange, runIcmp, onRunIcmpChange, recentHitDays, onRecentHitDaysChange, busy, progress, lookupResult, lookupBusy, error, onLookup, onAddLookupEntities, onAnalyze, onOpenConnection }: CleanupPageProps) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<WorkMode>("point");
  const [activeKind, setActiveKind] = useState<TargetKind>("policy");
  const [lookupKind, setLookupKind] = useState<LookupKind>("policy");
  const [lookupText, setLookupText] = useState("");
  const [lookupDg, setLookupDg] = useState("");
  const [selectedLookup, setSelectedLookup] = useState<Set<string>>(new Set());
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [expandedLookup, setExpandedLookup] = useState<Set<string>>(new Set());
  const parsed = useMemo(() => ({
    ip: parseAddressInput(targetTexts.ip),
    object: parseNameInput(targetTexts.object),
    group: parseNameInput(targetTexts.group),
    policy: parseNameInput(targetTexts.policy),
  }), [targetTexts]);
  const lookupNames = useMemo(
    () => lookupKind === "ip" ? parseAddressInput(lookupText).addresses : parseNameInput(lookupText).names,
    [lookupKind, lookupText],
  );
  const activeParsed = parsed[activeKind];
  const counts: Record<TargetKind, number> = { ip: parsed.ip.addresses.length, object: parsed.object.names.length, group: parsed.group.names.length, policy: parsed.policy.names.length };
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const activeCount = counts[activeKind];
  const inspected = lookupResult?.found.find((item) => item.id === inspectedId) ?? lookupResult?.found[0] ?? null;
  const chosenLookup = lookupResult?.found.filter((item) => selectedLookup.has(item.id)) ?? [];

  const loadFile = async (file?: File) => {
    if (!file) return;
    onTargetTextChange(activeKind, await file.text());
  };

  const addToBatch = (items: LookupEntity[]) => {
    onAddLookupEntities(items);
    setMode("batch");
  };

  const toggleLookup = (id: string) => setSelectedLookup((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  return (
    <div className="page-stack cleanup-design-page">
      <PageHeader eyebrow="Workflow / Cleanup" title="Wyszukaj, sprawdź zależności, usuń" description="Tryb punktowy odpytuje dokładny XPath bez pobierania całego configu. Batch pobiera snapshot raz, buduje graf i zapisuje backup każdej encji." />

      {!connection && <Callout severity="warning" title="Najpierw połącz się z Panorama" actions={<Button onClick={onOpenConnection}>Przejdź do połączenia</Button>}><p>Wyszukiwanie i analiza wymagają aktywnej sesji. WRITE nie jest potrzebny.</p></Callout>}
      {error && <Callout severity="danger" title="Operacja nie powiodła się"><p>{error}</p></Callout>}

      <div className="cleanup-mode-switch" role="tablist" aria-label="Tryb wyszukiwania">
        <button className={mode === "point" ? "is-active" : ""} onClick={() => setMode("point")}><Search size={17} /><span><strong>Punktowo</strong><small>1–20 dokładnych wartości · wąskie XPath</small></span></button>
        <button className={mode === "batch" ? "is-active" : ""} onClick={() => setMode("batch")}><Boxes size={17} /><span><strong>Lista / batch</strong><small>Pełny graf zależności · cache sesji</small></span></button>
      </div>

      {mode === "point" ? (
        <div className="lookup-workspace">
          <Card className="lookup-search-pane">
            <CardHeader title="Dokładne wyszukiwanie" description="Bez fuzzy match i bez pełnego /config." action={<Search size={20} />} />
            <div className="lookup-kind-chips">{lookupOptions.map((option) => <button key={option.id} className={lookupKind === option.id ? "is-active" : ""} onClick={() => { setLookupKind(option.id); setSelectedLookup(new Set()); }}>{option.label}</button>)}</div>
            <label className="field"><span>Nazwa / wartość <small>maks. 20</small></span><textarea className="lookup-input" value={lookupText} onChange={(event) => setLookupText(event.target.value)} placeholder={lookupKind === "policy" ? "ALLOW-APP-01\nDNAT-SERVICE-02" : lookupKind === "ip" ? "10.20.30.40" : "dokładna-nazwa"} spellCheck={false} /></label>
            <label className="field"><span>Device group <small>opcjonalnie — szybciej</small></span><input value={lookupDg} onChange={(event) => setLookupDg(event.target.value)} placeholder="puste = shared + wszystkie DG" spellCheck={false} /></label>
            <Button variant="primary" loading={lookupBusy} disabled={!connection || !lookupNames.length || lookupNames.length > 20} onClick={() => onLookup(lookupKind, lookupNames, lookupDg)} icon={<Search size={17} />}>Znajdź dokładnie</Button>
            {lookupBusy && <div className="lookup-live-progress" role="status"><div><LoaderCircle className="spin" size={17} /><strong>Wąskie zapytania XML API</strong></div><span><i /></span><small>shared / DG · maksymalnie 8 równoległych odczytów</small></div>}
            <div className="lookup-safety"><ShieldCheck size={17} /><span>Ten ekran niczego nie zapisuje. Application Override i DAG zostaną oznaczone jako read-only.</span></div>
          </Card>

          <Card className="lookup-results-pane">
            <CardHeader title="Wyniki" description={lookupResult ? `${lookupResult.found.length} znalezionych · ${lookupResult.apiCalls} zapytań · ${(lookupResult.elapsedMs / 1000).toLocaleString("pl-PL", { maximumFractionDigits: 2 })} s` : "Uruchom wyszukiwanie po dokładnej nazwie."} action={lookupResult && <StatusPill tone={lookupResult.partial ? "warning" : "success"}>{lookupResult.partial ? "wynik częściowy" : "exact match"}</StatusPill>} />
            {lookupResult?.warnings.map((warning) => <Callout key={warning} severity="warning" title="Informacja z lookup"><p>{warning}</p></Callout>)}
            {!lookupResult?.found.length ? <div className="lookup-empty"><Search size={28} /><strong>{lookupResult ? "Nie znaleziono dokładnego dopasowania" : "Wyniki pojawią się tutaj"}</strong><span>Możesz ograniczyć wyszukiwanie do konkretnego DG.</span></div> : <div className="lookup-result-list">
              {lookupResult.found.map((item) => {
                const expanded = expandedLookup.has(item.id);
                return <div key={item.id} className={`lookup-result ${inspected?.id === item.id ? "is-inspected" : ""}`}>
                  <div className="lookup-result__main" onClick={() => setInspectedId(item.id)}>
                    <input type="checkbox" checked={selectedLookup.has(item.id)} disabled={item.readOnly} onClick={(event) => event.stopPropagation()} onChange={() => toggleLookup(item.id)} aria-label={`Zaznacz ${item.name}`} />
                    <span className={`entity-type-dot entity-type-dot--${item.type}`} />
                    <span><strong>{item.name}</strong><small>{item.scope} · {item.rulebase ?? item.type} · {item.policyType ?? item.value}</small></span>
                    {item.type === "policy" && <span className={lastHitClass(item)}><b>{item.hitCount ?? 0} hit</b><small>{item.lastHit ? formatDate(item.lastHit) : "brak Last Hit"}</small></span>}
                    {item.readOnly && <StatusPill tone="warning">Read-only</StatusPill>}
                    <button className="table-expand" onClick={(event) => { event.stopPropagation(); setExpandedLookup((current) => { const next = new Set(current); if (next.has(item.id)) next.delete(item.id); else next.add(item.id); return next; }); }} aria-label={`Rozwiń ${item.name}`}>{expanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}</button>
                  </div>
                  {expanded && <div className="lookup-result__dependencies"><strong>Zależności wychodzące ({item.dependencies.length})</strong>{item.dependencies.length ? item.dependencies.map((dependency) => <div key={dependency.id}><ListTree size={15} /><span><b>{dependency.name}</b><small>{dependency.relation} · {dependency.scope}</small></span></div>) : <span className="muted-value">Brak zależności adresowych w regule/obiekcie.</span>}</div>}
                </div>;
              })}
            </div>}
            {chosenLookup.length > 0 && <div className="lookup-selection-bar"><span><strong>{chosenLookup.length}</strong> zaznaczonych</span><Button variant="primary" onClick={() => addToBatch(chosenLookup)} icon={<ArrowRight size={16} />}>Dodaj do bezpiecznego planu</Button></div>}
          </Card>

          <Card className="lookup-inspector-pane">
            <CardHeader title="Inspektor" description="Pola zwrócone przez Panorama." action={<ListTree size={20} />} />
            {!inspected ? <div className="lookup-empty"><ListTree size={28} /><strong>Wybierz wynik</strong><span>Zobaczysz DG, rulebase, strefy, tagi, adresy, service, app i komentarz.</span></div> : <>
              <div className="inspector-title"><div><span className={`entity-type-dot entity-type-dot--${inspected.type}`} /><span><strong>{inspected.name}</strong><small>{inspected.type}</small></span></div>{inspected.readOnly ? <StatusPill tone="warning">Read-only</StatusPill> : <StatusPill tone="success">Planowalny</StatusPill>}</div>
              {inspected.blockedReason && <Callout severity="warning" title="Automatyczne usunięcie zablokowane"><p>{inspected.blockedReason}</p></Callout>}
              <dl className="inspector-fields">{inspected.fields.map((field, index) => <div key={`${field.k}-${index}`}><dt>{field.k}</dt><dd>{field.v}</dd></div>)}</dl>
              {inspected.type === "policy" && <div className={`inspector-hit ${lastHitClass(inspected)}`}><span><strong>Last Hit</strong><b>{inspected.hitCount ?? 0} trafień</b></span><p>{inspected.lastHit ? formatDate(inspected.lastHit) : "Brak Last Hit / brak hitów"}</p><small>{inspected.lastHitDetail}</small></div>}
              <div className="inspector-dependencies"><h3>Zależności ({inspected.dependencies.length})</h3>{inspected.dependencies.map((dependency) => <div key={dependency.id}><ListTree size={15} /><span><strong>{dependency.name}</strong><small>{dependency.relation} · {dependency.scope}</small></span></div>)}</div>
              {!inspected.readOnly && <Button variant="primary" onClick={() => addToBatch([inspected])}>Dodaj ten element do planu</Button>}
              <code className="inspector-xpath">{inspected.xpath}</code>
            </>}
          </Card>
        </div>
      ) : (
        <div className="cleanup-layout">
          <Card className="address-input-card">
            <CardHeader title="Lista wejściowa" description="Wklej dużą paczkę. Snapshot zostanie pobrany raz i zachowany w cache bieżącego połączenia." action={<FileText size={20} />} />
            <div className="target-kind-tabs" role="tablist">{(Object.keys(targetOptions) as TargetKind[]).map((kind) => <button key={kind} type="button" role="tab" className={activeKind === kind ? "is-active" : ""} onClick={() => setActiveKind(kind)}>{targetOptions[kind].label}<span>{counts[kind]}</span></button>)}</div>
            <div className="address-editor-wrap">
              <div className="address-editor__toolbar"><div><span className="editor-count">{activeCount}</span><span>{activeKind === "ip" ? pluralize(activeCount, ["unikalny adres", "unikalne adresy", "unikalnych adresów"]) : pluralize(activeCount, ["unikalna nazwa", "unikalne nazwy", "unikalnych nazw"])}</span></div><button type="button" onClick={() => fileRef.current?.click()}><Upload size={15} /> Wczytaj .txt</button><input ref={fileRef} type="file" accept=".txt,text/plain" hidden onChange={(event) => void loadFile(event.target.files?.[0])} /></div>
              <textarea className="address-editor" value={targetTexts[activeKind]} onChange={(event) => onTargetTextChange(activeKind, event.target.value)} placeholder={targetOptions[activeKind].placeholder} spellCheck={false} aria-label={`${targetOptions[activeKind].label} do cleanupu`} />
              <p className="editor-hint">{targetOptions[activeKind].hint}</p>
              <div className="address-editor__footer"><span>Duplikaty: <strong>{activeParsed.duplicates}</strong></span><span>Komentarze: <strong>{activeParsed.ignored}</strong></span><button type="button" onClick={() => onTargetTextChange(activeKind, "")} disabled={!targetTexts[activeKind]}>Wyczyść</button></div>
            </div>
          </Card>

          <div className="cleanup-options">
            <Card><CardHeader title="Kontrole przed planem" description="Live walidacja nastąpi ponownie przed zapisem Candidate." action={<Radar size={20} />} /><div className="option-stack"><Toggle checked={runIcmp} onChange={onRunIcmpChange} label="Sprawdź ICMP" description="Odpowiedź lub błąd lokalny pomija IP; nie dotyczy nazw polityk i obiektów." /><label className="range-field"><div><strong>Próg świeżego Last Hit</strong><span>Kolorystyka wyniku pozostaje stała: 14 dni / miesiąc / pół roku.</span></div><div className="range-field__control"><input type="range" min="7" max="90" step="1" value={recentHitDays} onChange={(event) => onRecentHitDaysChange(Number(event.target.value))} /><output>{recentHitDays} dni</output></div></label></div></Card>
            <Card><CardHeader title="Zakres grafu" description="Security, NAT, Application Override i grupy zagnieżdżone." action={<Workflow size={20} />} /><div className="scope-grid"><div><ShieldCheck size={18} /><span><strong>Security</strong><small>source · destination</small></span></div><div><Network size={18} /><span><strong>NAT</strong><small>rules · translation</small></span></div><div><Gauge size={18} /><span><strong>App Override</strong><small>wykrywane jako read-only</small></span></div><div><Workflow size={18} /><span><strong>Grupy</strong><small>pełne zależności</small></span></div></div></Card>
            <div className="analysis-preview"><StatCard label="Do sprawdzenia" value={total} detail="po deduplikacji" tone="accent" /><StatCard label="Snapshot" value="Cache 30 min" detail="kolejny batch bez ponownego downloadu" /><StatCard label="Zmiany" value="0" detail="analiza jest READ ONLY" tone="success" /></div>
            <Callout severity="info" title="Co stanie się przy WRITE?"><p>Toolbox nie ładuje całego configu. Po backupie i sprawdzeniu locków wykonuje osobne operacje XPath XML API, jedna po drugiej, z fingerprintem każdej ścieżki.</p></Callout>
            <Button className="analyze-button" variant="primary" onClick={onAnalyze} loading={busy} disabled={!connection || total === 0} icon={<ArrowRight size={18} />}>Analizuj zależności i przygotuj backupy</Button>
            {busy && progress && <Card className="analysis-progress" aria-live="polite"><div><strong>{progress.message}</strong><span>{progress.progress}%</span></div><ProgressBar value={progress.progress} label={`${progress.progress}%`} /><small>Pierwszy batch pobiera snapshot; kolejne korzystają ze świeżego cache sesji.</small></Card>}
            {total > 500 && <div className="inline-warning"><AlertTriangle size={16} /> Duża paczka może potrwać kilka minut. Postęp faz będzie widoczny na tym ekranie.</div>}
          </div>
        </div>
      )}
    </div>
  );
}
