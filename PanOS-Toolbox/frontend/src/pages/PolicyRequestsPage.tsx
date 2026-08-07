import { ArrowRight, FileText, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import type { CleanupPlan } from "../model";
import { Button, Callout, Card, CardHeader, PageHeader, StatCard } from "../components/Primitives";

interface PolicyRequestsPageProps {
  connection: boolean;
  busy: boolean;
  error: string | null;
  plan: CleanupPlan | null;
  onCreatePlan: (text: string) => void;
  onOpenConnection: () => void;
  onOpenPlan: () => void;
}

const example = `API Answer Success: true

Passes ToDo
['[GRUPA/USER AD] -> <IP> | <PORT>-tcp |  | bezterminowo']

Info Src
{
  '[GRUPA/USER AD]': {
    'IdType': 'paloGroup',
    'dynamicIp': '<IP>',
    'zone': '<ZONE>',
    'subnet': '<IP>/21',
    'device': '<DEVICE>'
  }
}

Info Dst
{
  '<IP>': {
    'dns': '<DOMAIN>',
    'zone': '<ZONE>',
    'subnet': '<IP>/24',
    'device': '<DEVICE>',
    'hg': 'none'
  }
}`;

export function PolicyRequestsPage({ connection, busy, error, plan, onCreatePlan, onOpenConnection, onOpenPlan }: PolicyRequestsPageProps) {
  const [text, setText] = useState("");
  const lineCount = useMemo(() => text ? text.split(/\r?\n/).length : 0, [text]);
  return (
    <div className="page-stack policy-requests-page">
      <PageHeader eyebrow="Workflow / Add / Policy request" title="Utwórz polityki z wklejki" description="Wklej dokładny eksport zlecenia. Toolbox rozpozna Passes ToDo, Info Src/Info Dst, sprawdzi obiekty punktowym XML API i przygotuje plan w odpowiednim DG, rulebase oraz strefach." />
      {!connection && <Callout severity="warning" title="Najpierw połącz się z Panorama" actions={<Button onClick={onOpenConnection}>Przejdź do połączenia</Button>}><p>Parser działa lokalnie, ale sprawdzenie istnienia obiektów i polityk wymaga aktywnej sesji.</p></Callout>}
      {error && <Callout severity="danger" title="Nie udało się przygotować planu"><p>{error}</p></Callout>}
      <div className="policy-request-layout">
        <Card className="policy-request-input-card">
          <CardHeader title="Wklejka zlecenia" description="Obsługiwany jest JSON, Python repr oraz mieszany eksport z komentarzami //." action={<FileText size={20} />} />
          <textarea className="policy-request-editor" value={text} onChange={(event) => setText(event.target.value)} placeholder={example} spellCheck={false} aria-label="Wklejka zlecenia utworzenia polityk" />
          <div className="address-editor__footer"><span>Wiersze: <strong>{lineCount}</strong></span><span>Źródło: <strong>Passes ToDo</strong></span><button type="button" onClick={() => setText(example)}>Wstaw przykład</button><button type="button" onClick={() => setText("")} disabled={!text}>Wyczyść</button></div>
          <Button variant="primary" loading={busy} disabled={!connection || !text.trim()} onClick={() => onCreatePlan(text)} icon={<ArrowRight size={18} />}>Sprawdź obiekty i przygotuj plan</Button>
        </Card>
        <div className="policy-request-info">
          <Card><CardHeader title="Co zostanie przygotowane" description="Żaden zapis nie uruchamia się automatycznie." action={<ShieldCheck size={20} />} /><div className="policy-request-checklist"><div><strong>H- / N-</strong><span>Obiekty hostów i sieci z IP oraz maski.</span></div><div><strong>HG__</strong><span>Grupy hostów z pola hg, jeśli są wymagane.</span></div><div><strong>DG + strefy</strong><span>Device group, from/to oraz pre-rulebase/security.</span></div><div><strong>API XPath</strong><span>Każdy obiekt i polityka ma osobny backup i rollback.</span></div></div></Card>
          {plan && <Card className="policy-request-result"><CardHeader title="Plan gotowy" description={`${plan.operations.length} operacji · ${plan.affectedDeviceGroups.join(", ") || "shared"}`} /><StatCard label="Przepływy" value={plan.addresses.length} detail="z wklejki" tone="accent" /><StatCard label="Nowe mutacje" value={plan.operations.length} detail="do Candidate" tone={plan.operations.length ? "success" : "warning"} /><Button variant="primary" onClick={onOpenPlan}>Otwórz plan i Execute</Button></Card>}
        </div>
      </div>
      <Callout severity="info" title="Kontrola przed zapisem"><p>Istniejące obiekty/polityki są pomijane z ostrzeżeniem. Placeholdery można wklejać dokładnie tak jak w zgłoszeniu; przed Candidate sprawdź wygenerowane nazwy, DG, XPath, source-user oraz tagi.</p></Callout>
    </div>
  );
}
