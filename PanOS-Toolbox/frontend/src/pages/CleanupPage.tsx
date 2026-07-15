import { AlertTriangle, ArrowRight, FileText, Gauge, Network, Radar, ShieldCheck, Upload, Workflow } from "lucide-react";
import { useMemo, useRef } from "react";
import type { ConnectionSession } from "../model";
import { parseAddressInput, pluralize } from "../utils";
import { Button, Callout, Card, CardHeader, PageHeader, StatCard, Toggle } from "../components/Primitives";

interface CleanupPageProps {
  connection: ConnectionSession | null;
  addressText: string;
  onAddressTextChange: (value: string) => void;
  runIcmp: boolean;
  onRunIcmpChange: (value: boolean) => void;
  recentHitDays: number;
  onRecentHitDaysChange: (value: number) => void;
  busy: boolean;
  error: string | null;
  onAnalyze: () => void;
  onOpenConnection: () => void;
}

export function CleanupPage({ connection, addressText, onAddressTextChange, runIcmp, onRunIcmpChange, recentHitDays, onRecentHitDaysChange, busy, error, onAnalyze, onOpenConnection }: CleanupPageProps) {
  const fileRef = useRef<HTMLInputElement>(null);
  const parsed = useMemo(() => parseAddressInput(addressText), [addressText]);

  const loadFile = async (file?: File) => {
    if (!file) return;
    onAddressTextChange(await file.text());
  };

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Workflow / Cleanup"
        title="Wskaż adresy do analizy"
        description="Toolbox rozwiąże dokładne nazwy obiektów, pełną sieć zależności oraz bezpieczny plan zmian na podstawie running config."
      />

      {!connection && <Callout severity="warning" title="Najpierw połącz się z Panorama" actions={<Button onClick={onOpenConnection}>Przejdź do połączenia</Button>}><p>Analiza wymaga aktywnej sesji odczytowej. Włączenie zapisu nie jest potrzebne.</p></Callout>}
      {error && <Callout severity="danger" title="Analiza nie powiodła się"><p>{error}</p></Callout>}

      <div className="cleanup-layout">
        <Card className="address-input-card">
          <CardHeader title="Lista wejściowa" description="Jeden adres w wierszu; komentarze po # są ignorowane." action={<FileText size={20} />} />
          <div className="address-editor-wrap">
            <div className="address-editor__toolbar">
              <div>
                <span className="editor-count">{parsed.addresses.length}</span>
                <span>{pluralize(parsed.addresses.length, ["unikalny adres", "unikalne adresy", "unikalnych adresów"])}</span>
              </div>
              <button type="button" onClick={() => fileRef.current?.click()}><Upload size={15} /> Wczytaj ip.txt</button>
              <input ref={fileRef} type="file" accept=".txt,text/plain" hidden onChange={(event) => void loadFile(event.target.files?.[0])} />
            </div>
            <textarea
              className="address-editor"
              value={addressText}
              onChange={(event) => onAddressTextChange(event.target.value)}
              placeholder={"10.20.30.41\n10.20.30.42\n# wycofane serwery"}
              spellCheck={false}
              aria-label="Adresy IP do cleanupu"
            />
            <div className="address-editor__footer">
              <span>Duplikaty: <strong>{parsed.duplicates}</strong></span>
              <span>Komentarze: <strong>{parsed.ignored}</strong></span>
              <button type="button" onClick={() => onAddressTextChange("")} disabled={!addressText}>Wyczyść</button>
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
            <StatCard label="Do sprawdzenia" value={parsed.addresses.length} detail="po deduplikacji" tone="accent" />
            <StatCard label="Tryb" value="Running" detail="źródło analizy" />
            <StatCard label="Zmiany" value="0" detail="plan nie zapisuje API" tone="success" />
          </div>

          <Callout severity="info" title="Diff jest informacją"><p>Natywny change-summary i diff semantyczny pojawią się w planie. Istniejący candidate nie blokuje generowania.</p></Callout>

          <Button className="analyze-button" variant="primary" onClick={onAnalyze} loading={busy} disabled={!connection || parsed.addresses.length === 0} icon={<ArrowRight size={18} />}>
            Analizuj zależności
          </Button>
          {parsed.addresses.length > 500 && <div className="inline-warning"><AlertTriangle size={16} /> Duża paczka może potrwać kilka minut. Postęp będzie raportowany przez backend.</div>}
        </div>
      </div>
    </div>
  );
}
