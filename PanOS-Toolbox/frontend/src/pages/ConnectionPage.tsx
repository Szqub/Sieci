import { CircleGauge, FlaskConical, KeyRound, LoaderCircle, LockKeyhole, Radar, Server, ShieldCheck, Wifi } from "lucide-react";
import type { ConnectionDraft, ConnectionSession, DoctorResult } from "../model";
import { formatDate } from "../model";
import { Button, Callout, Card, CardHeader, PageHeader, ResultIcon, StatusPill, Toggle } from "../components/Primitives";

interface ConnectionPageProps {
  draft: ConnectionDraft;
  onDraftChange: (draft: ConnectionDraft) => void;
  connection: ConnectionSession | null;
  doctor: DoctorResult | null;
  busy: "connect" | "doctor" | null;
  error: string | null;
  onConnect: () => void;
  onDoctor: () => void;
  onDemo: () => void;
  demoAvailable: boolean;
}

export function ConnectionPage({ draft, onDraftChange, connection, doctor, busy, error, onConnect, onDoctor, onDemo, demoAvailable }: ConnectionPageProps) {
  const update = <K extends keyof ConnectionDraft>(key: K, value: ConnectionDraft[K]) => onDraftChange({ ...draft, [key]: value });

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Workspace / Connection"
        title="Połącz Toolbox z Panorama"
        description="Poświadczenia żyją wyłącznie w pamięci procesu. Połączenie wykonuje keygen, odczyt prawdziwej wersji systemu i status Candidate — nie pobiera całej konfiguracji."
        actions={connection && <StatusPill tone="success">Połączono · {connection.panoramaVersion}</StatusPill>}
      />

      {error && <Callout severity="danger" title="Nie udało się wykonać operacji"><p>{error}</p></Callout>}

      <div className="connection-grid">
        <Card className="connection-form-card">
          <CardHeader title="Połączenie z Panorama" description="Jeden przełącznik READ ONLY / WRITE znajduje się stale w górnym pasku." action={<Server size={20} />} />
          <form onSubmit={(event) => { event.preventDefault(); onConnect(); }} className="form-stack" autoComplete="off">
            <div className="field-grid field-grid--2">
              <label className="field">
                <span>Host Panorama</span>
                <div className="input-with-icon"><Server size={17} /><input value={draft.host} onChange={(event) => update("host", event.target.value)} placeholder="10.20.30.40 lub panorama.local" required spellCheck={false} /></div>
              </label>
              <label className="field">
                <span>Użytkownik</span>
                <div className="input-with-icon"><ShieldCheck size={17} /><input value={draft.username} onChange={(event) => update("username", event.target.value)} placeholder="superadmin" required autoComplete="username" /></div>
              </label>
            </div>
            <label className="field">
              <span>Hasło <small>nie zostanie zapisane</small></span>
              <div className="input-with-icon"><KeyRound size={17} /><input type="password" value={draft.password} onChange={(event) => update("password", event.target.value)} placeholder="••••••••••••" required autoComplete="current-password" /></div>
            </label>

            <div className="setting-panel">
              <Toggle checked={draft.ssl} onChange={(value) => onDraftChange({ ...draft, ssl: value, verifySsl: value ? draft.verifySsl : false })} label="HTTPS / SSL" description={draft.ssl ? "Połączenie przez HTTPS" : "Połączenie HTTP — tylko dla zaufanej sieci administracyjnej"} />
              <Toggle checked={draft.verifySsl} onChange={(value) => update("verifySsl", value)} label="Weryfikuj certyfikat" description={draft.verifySsl ? "Łańcuch certyfikatu musi być zaufany" : "Odpowiednik --insecure; tożsamość hosta nie jest weryfikowana"} disabled={!draft.ssl} danger={draft.ssl && !draft.verifySsl} />
            </div>

            {!draft.verifySsl && draft.ssl && <Callout severity="warning" title="Certyfikat nie będzie weryfikowany"><p>Połączenie jest szyfrowane, ale podatne na podszycie się pod urządzenie. Używaj wyłącznie w kontrolowanej sieci.</p></Callout>}

            <div className="form-actions">
              <Button type="button" onClick={onDoctor} loading={busy === "doctor"} icon={<CircleGauge size={17} />}>Uruchom Doctor</Button>
              <Button type="submit" variant="primary" loading={busy === "connect"} icon={<Wifi size={17} />}>{connection ? "Połącz ponownie" : "Połącz"}</Button>
            </div>
            {busy === "connect" && (
              <div className="connection-progress" role="status" aria-live="polite">
                <div><LoaderCircle className="spin" size={18} /><span><strong>Łączenie z Panorama</strong><small>Keygen → show system info → status Candidate</small></span></div>
                <span className="connection-progress__track"><i /></span>
                <p>Pełny running/candidate zostanie pobrany dopiero po uruchomieniu analizy batch.</p>
              </div>
            )}
          </form>
          {demoAvailable && (
            <button className="demo-link" type="button" onClick={onDemo}><FlaskConical size={15} /> Otwórz bezpieczne dane demonstracyjne</button>
          )}
        </Card>

        <div className="connection-side">
          <Card>
            <CardHeader title="Environment Doctor" description="Kontrole gotowości środowiska i API." action={<Radar size={20} />} />
            {!doctor ? (
              <div className="doctor-placeholder">
                <CircleGauge size={32} />
                <strong>Brak wyniku diagnostyki</strong>
                <p>Doctor sprawdzi localhost, katalog sesji, assety GUI oraz transport TCP/TLS do Panorama.</p>
              </div>
            ) : (
              <div className="doctor-list">
                {doctor.checks.map((check) => (
                  <div className="doctor-item" key={check.id}>
                    <ResultIcon state={check.state} />
                    <div><strong>{check.label}</strong><span>{check.detail}</span></div>
                    {check.durationMs !== undefined && <small>{check.durationMs} ms</small>}
                  </div>
                ))}
                <span className="doctor-timestamp">Sprawdzono {formatDate(doctor.generatedAt)}</span>
              </div>
            )}
          </Card>

          <Card className="safety-card">
            <LockKeyhole size={22} />
            <div><h2>Granice bezpieczeństwa</h2><p>Backend nasłuchuje tylko na 127.0.0.1. Hasło i API key nie trafiają do plików, historii ani storage przeglądarki.</p></div>
          </Card>

          <Card>
            <CardHeader title="Dwa tryby pracy" description="Bez ukrytych profili ani dodatkowych limitów GUI." />
            <div className="connection-modes"><div><span>READ ONLY</span><strong>Wyszukiwanie, analiza, Last Hit i backupy</strong></div><div><span>WRITE</span><strong>Operacje XPath → Candidate → Commit → Push</strong></div></div>
          </Card>
        </div>
      </div>
    </div>
  );
}
