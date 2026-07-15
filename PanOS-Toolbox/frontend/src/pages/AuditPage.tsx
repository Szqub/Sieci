import { CheckCircle2, Crosshair, FileSearch, ListTree, Radar, Search, ShieldQuestion } from "lucide-react";
import { useMemo, useState } from "react";
import type { AuditResult, ConnectionSession } from "../model";
import { formatDate } from "../model";
import { parseAddressInput } from "../utils";
import { Button, Callout, Card, CardHeader, EmptyState, PageHeader, StatCard, StatusPill } from "../components/Primitives";

interface AuditPageProps {
  connection: ConnectionSession | null;
  query: string;
  onQueryChange: (query: string) => void;
  result: AuditResult | null;
  busy: boolean;
  error: string | null;
  onAudit: () => void;
  onOpenConnection: () => void;
}

export function AuditPage({ connection, query, onQueryChange, result, busy, error, onAudit, onOpenConnection }: AuditPageProps) {
  const [filter, setFilter] = useState("");
  const parsed = useMemo(() => parseAddressInput(query), [query]);
  const references = useMemo(() => result?.addresses.flatMap((address) => address.references.map((reference) => ({ address, reference }))).filter(({ address, reference }) => {
    const haystack = `${address.ip} ${address.objectNames.join(" ")} ${reference.name} ${reference.deviceGroup} ${reference.policyType}`.toLowerCase();
    return haystack.includes(filter.toLowerCase());
  }) ?? [], [result, filter]);

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Verification / Audit" title="Sprawdź, co pozostało" description="Ponowny odczyt running config pokazuje dokładne nazwy obiektów, grupy, polityki, rulebase i wszystkie wspierane referencje." />
      {!connection && <Callout severity="warning" title="Brak aktywnego połączenia" actions={<Button onClick={onOpenConnection}>Połącz</Button>}><p>Audit jest operacją wyłącznie odczytową, ale wymaga sesji Panorama.</p></Callout>}
      {error && <Callout severity="danger" title="Audit nie powiódł się"><p>{error}</p></Callout>}

      <Card className="audit-query-card">
        <div className="audit-query-copy"><div className="feature-icon"><FileSearch size={21} /></div><div><h2>Adresy do ponownego sprawdzenia</h2><p>Wklej poprzednią listę lub pojedynczy adres. ICMP nie wpływa na wynik audytu.</p></div></div>
        <div className="audit-query-input"><textarea value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder={"10.42.16.19\n10.42.16.20"} aria-label="Adresy do audytu" spellCheck={false} /><div><span>{parsed.addresses.length} adresów</span><Button variant="primary" icon={<Radar size={17} />} loading={busy} disabled={!connection || parsed.addresses.length === 0} onClick={onAudit}>Uruchom Audit</Button></div></div>
      </Card>

      {!result ? (
        <Card><EmptyState icon={<ShieldQuestion size={28} />} title="Czekam na zakres audytu" description="Wynik rozdzieli czyste adresy, nieistniejące obiekty i każdą pozostałą referencję." /></Card>
      ) : (
        <>
          <div className="stats-grid stats-grid--4">
            <StatCard label="Sprawdzone" value={result.addresses.length} detail={`stan z ${formatDate(result.generatedAt)}`} />
            <StatCard label="Bez referencji" value={result.cleanCount} detail="czyste" tone="success" />
            <StatCard label="Referencje" value={result.residualReferenceCount} detail="wymagają uwagi" tone={result.residualReferenceCount ? "warning" : "success"} />
            <StatCard label="Tryb" value="Read-only" detail="zero zmian API" tone="accent" />
          </div>

          {result.residualReferenceCount === 0 && <Callout severity="success" title="Nie znaleziono pozostałości"><p>W obsługiwanych namespace’ach running config nie ma referencji do podanych adresów.</p></Callout>}

          <Card>
            <CardHeader title="Wyniki per adres" description="Rozwinięcie pokazuje lokalizacje XPath i dokładne nazwy encji." action={<Crosshair size={20} />} />
            <div className="audit-address-grid">
              {result.addresses.map((address) => (
                <div key={address.ip} className={`audit-address-card ${address.references.length ? "has-references" : "is-clean"}`}>
                  <div className="audit-address-card__head">
                    <div>{address.references.length ? <ListTree size={18} /> : <CheckCircle2 size={18} />}<span><strong>{address.ip}</strong><small>{address.objectNames.join(", ") || "obiekt nie istnieje"}</small></span></div>
                    <StatusPill tone={address.references.length ? "warning" : "success"}>{address.references.length ? `${address.references.length} ref.` : "Czysty"}</StatusPill>
                  </div>
                  {address.references.map((reference) => <div className="audit-reference" key={reference.id}><div><strong>{reference.name}</strong><StatusPill tone="neutral" dot={false}>{reference.policyType}</StatusPill></div><span>{reference.deviceGroup} · {reference.rulebase}-rulebase · {reference.field}</span><code>{reference.path}</code></div>)}
                </div>
              ))}
            </div>
          </Card>

          {references.length > 0 && <Card>
            <CardHeader title="Spis wszystkich referencji" description="Widok do szybkiego filtrowania i przekazania administratorowi." action={<div className="table-search"><Search size={15} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filtruj DG, regułę, adres…" /></div>} />
            <div className="responsive-table"><table><thead><tr><th>Adres / obiekt</th><th>Device Group</th><th>Rulebase</th><th>Typ</th><th>Encja</th><th>Pole</th></tr></thead><tbody>{references.map(({ address, reference }) => <tr key={`${address.ip}-${reference.id}`}><td><div className="entity-cell"><strong>{address.ip}</strong><small>{address.objectNames.join(", ")}</small></div></td><td>{reference.deviceGroup}</td><td>{reference.rulebase}</td><td>{reference.policyType}</td><td>{reference.name}</td><td><code>{reference.field}</code></td></tr>)}</tbody></table></div>
          </Card>}
        </>
      )}
    </div>
  );
}
