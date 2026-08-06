import { AlertTriangle, ArrowRight, FileText, Gauge, Network, Radar, ShieldCheck, Upload, Workflow } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import type { AnalysisJob, ConnectionSession } from "../model";
import { parseAddressInput, parseNameInput, pluralize } from "../utils";
import { Button, Callout, Card, CardHeader, PageHeader, ProgressBar, StatCard, Toggle } from "../components/Primitives";

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
  error: string | null;
  onAnalyze: () => void;
  onOpenConnection: () => void;
}

type TargetKind = "ip" | "object" | "group" | "policy";

const targetOptions: Record<TargetKind, { label: string; hint: string; placeholder: string }> = {
  ip: { label: "IP / literal", hint: "Adresy IP; można rozdzielać spacją, przecinkiem lub nową linią.", placeholder: "10.20.30.41\n10.20.30.42\n# wycofane serwery" },
  object: { label: "Obiekty", hint: "Dokładna nazwa obiektu adresowego w każdym wierszu.", placeholder: "OLD-WEB-SERVER\nOLD-DATABASE" },
  group: { label: "Grupy", hint: "Dokładna nazwa statycznej address group w każdym wierszu.", placeholder: "GRP-LEGACY-SERVERS\nGRP-OLD-DMZ" },
  policy: { label: "Polityki", hint: "Dokładna nazwa polityki w każdym wierszu; spacje w nazwie są zachowywane.", placeholder: "ALLOW LEGACY APP\nOLD-NAT-RULE" },
};

export function CleanupPage({ connection, targetTexts, onTargetTextChange, runIcmp, onRunIcmpChange, recentHitDays, onRecentHitDaysChange, busy, progress, error, onAnalyze, onOpenConnection }: CleanupPageProps) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [activeKind, setActiveKind] = useState<TargetKind>("ip");
  const parsed = useMemo(() => ({
    ip: parseAddressInput(targetTexts.ip),
    object: parseNameInput(targetTexts.object),
    group: parseNameInput(targetTexts.group),
    policy: parseNameInput(targetTexts.policy),
  }), [targetTexts]);
  const activeParsed = parsed[activeKind];
  const counts: Record<TargetKind, number> = {
    ip: parsed.ip.addresses.length,
    object: parsed.object.names.length,
    group: parsed.group.names.length,
    policy: parsed.policy.names.length,
  };
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const activeCount = counts[activeKind];

  const loadFile = async (file?: File) => {
    if (!file) return;
    onTargetTextChange(activeKind, await file.text());
  };

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Workflow / Cleanup"
        title="Wskaż cele do analizy"
        description="Wklej IP, nazwy obiektów, grup lub polityk. Toolbox odnajdzie DG/rulebase, zależności i Last Hit przed wygenerowaniem planu."
      />

      {!connection && <Callout severity="warning" title="Najpierw połącz się z Panorama" actions={<Button onClick={onOpenConnection}>Przejdź do połączenia</Button>}><p>Analiza wymaga aktywnej sesji odczytowej. Włączenie zapisu nie jest potrzebne.</p></Callout>}
      {error && <Callout severity="danger" title="Analiza nie powiodła się"><p>{error}</p></Callout>}

      <div className="cleanup-layout">
        <Card className="address-input-card">
          <CardHeader title="Lista wejściowa" description="Duże paczki można wkleić bezpośrednio albo wczytać z pliku tekstowego." action={<FileText size={20} />} />
          <div className="target-kind-tabs" role="tablist">
            {(Object.keys(targetOptions) as TargetKind[]).map((kind) => {
              const count = counts[kind];
              return <button key={kind} type="button" role="tab" className={activeKind === kind ? "is-active" : ""} onClick={() => setActiveKind(kind)}>{targetOptions[kind].label}<span>{count}</span></button>;
            })}
          </div>
          <div className="address-editor-wrap">
            <div className="address-editor__toolbar">
              <div>
                <span className="editor-count">{activeCount}</span>
                <span>{activeKind === "ip" ? pluralize(activeCount, ["unikalny adres", "unikalne adresy", "unikalnych adresów"]) : pluralize(activeCount, ["unikalna nazwa", "unikalne nazwy", "unikalnych nazw"])}</span>
              </div>
              <button type="button" onClick={() => fileRef.current?.click()}><Upload size={15} /> Wczytaj ip.txt</button>
              <input ref={fileRef} type="file" accept=".txt,text/plain" hidden onChange={(event) => void loadFile(event.target.files?.[0])} />
            </div>
            <textarea
              className="address-editor"
              value={targetTexts[activeKind]}
              onChange={(event) => onTargetTextChange(activeKind, event.target.value)}
              placeholder={targetOptions[activeKind].placeholder}
              spellCheck={false}
              aria-label={`${targetOptions[activeKind].label} do cleanupu`}
            />
            <p className="editor-hint">{targetOptions[activeKind].hint}</p>
            <div className="address-editor__footer">
              <span>Duplikaty: <strong>{activeParsed.duplicates}</strong></span>
              <span>Komentarze: <strong>{activeParsed.ignored}</strong></span>
              <button type="button" onClick={() => onTargetTextChange(activeKind, "")} disabled={!targetTexts[activeKind]}>Wyczyść</button>
            </div>
          </div>
        </Card>

        <div className="cleanup-options">
          <Card>
            <CardHeader title="Kontrole przed planem" description="Wyniki wpływają na decyzję dla każdego adresu." action={<Radar size={20} />} />
            <div className="option-stack">
              <Toggle checked={runIcmp} onChange={onRunIcmpChange} label="Sprawdź ICMP" description="Odpowiedź lub błąd lokalny pomija adres; timeout kwalifikuje go do analizy." />
              <label className="range-field">
                <div><strong>Ostrzeżenie Last Hit</strong><span>Ruch nowszy niż próg zostanie oznaczony, lecz nie zablokuje planu.</span></div>
                <div className="range-field__control"><input type="range" min="7" max="30" step="1" value={recentHitDays} onChange={(event) => onRecentHitDaysChange(Number(event.target.value))} /><output>{recentHitDays} dni</output></div>
              </label>
            </div>
          </Card>

          <Card>
            <CardHeader title="Zakres analizy" description="Obsługiwane namespace’y PAN-OS 10.2." action={<Workflow size={20} />} />
            <div className="scope-grid">
              <div><ShieldCheck size={18} /><span><strong>Security</strong><small>source · destination</small></span></div>
              <div><Network size={18} /><span><strong>NAT</strong><small>rules · translation</small></span></div>
              <div><Gauge size={18} /><span><strong>App Override</strong><small>pre · post rulebase</small></span></div>
              <div><Workflow size={18} /><span><strong>Grupy</strong><small>zagnieżdżone zależności</small></span></div>
            </div>
          </Card>

          <div className="analysis-preview">
            <StatCard label="Do sprawdzenia" value={total} detail="łącznie, po deduplikacji" tone="accent" />
            <StatCard label="Tryb" value={total === 1 ? "Szybki" : "Batch"} detail={total === 1 ? "dokładny cel · cache połączenia" : "pełny running config"} />
            <StatCard label="Zmiany" value="0" detail="plan nie zapisuje API" tone="success" />
          </div>

          <Callout severity="info" title="Diff jest informacją"><p>Natywny change-summary i diff semantyczny pojawią się w planie. Istniejący candidate nie blokuje generowania.</p></Callout>

          {total === 1 && <Callout severity="success" title="Tryb pojedynczego celu"><p>Toolbox wyszuka dokładną nazwę w świeżym snapshotcie połączenia i utworzy osobną sesję. Pełny config zostanie odświeżony tylko wtedy, gdy cache zdążył wygasnąć.</p></Callout>}

          <Button className="analyze-button" variant="primary" onClick={onAnalyze} loading={busy} disabled={!connection || total === 0} icon={<ArrowRight size={18} />}>
            {total === 1 ? "Znajdź dokładny cel" : "Analizuj zależności"}
          </Button>
          {busy && progress && (
            <Card className="analysis-progress" aria-live="polite">
              <div><strong>{progress.message}</strong><span>{progress.progress}%</span></div>
              <ProgressBar value={progress.progress} label={`${progress.progress}%`} />
              <small>Możesz obserwować etap pobierania running/candidate i budowania grafu zależności.</small>
            </Card>
          )}
          {total > 500 && <div className="inline-warning"><AlertTriangle size={16} /> Duża paczka może potrwać kilka minut. Postęp będzie raportowany przez backend.</div>}
        </div>
      </div>
    </div>
  );
}
