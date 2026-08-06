import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
import type { ToolboxNotice } from "../model";
import { Card, EmptyState, PageHeader, StatusPill } from "../components/Primitives";

export function WarningsPage({ notices }: { notices: ToolboxNotice[] }) {
  const groups = useMemo(() => {
    const result = new Map<string, ToolboxNotice[]>();
    notices.forEach((notice) => result.set(notice.source, [...(result.get(notice.source) ?? []), notice]));
    return [...result.entries()];
  }, [notices]);

  return (
    <div className="page-stack warnings-page">
      <PageHeader
        eyebrow="Analiza / Uwagi"
        title="Uwagi, blokady i wyjątki w jednym miejscu"
        description="Ten widok zbiera informacje z lookup, planu, Application Override, AD i restore. Nie zasłania listy polityk ani przycisków wykonania."
        actions={<StatusPill tone={notices.length ? "warning" : "success"}>{notices.length ? `${notices.length} uwag` : "Bez uwag"}</StatusPill>}
      />

      {!notices.length ? (
        <Card><EmptyState icon={<CheckCircle2 size={28} />} title="Brak aktywnych uwag" description="Bieżąca analiza nie zgłosiła blokad ani elementów wymagających ręcznego przeglądu." /></Card>
      ) : (
        <Card className="warnings-board">
          <div className="warnings-board__summary">
            <span><AlertTriangle size={19} /><strong>{notices.length} elementów do przejrzenia</strong></span>
            <small>Pomarańczowy badge w sidebarze znika automatycznie po przygotowaniu nowej analizy bez uwag.</small>
          </div>
          {groups.map(([source, items]) => (
            <section className="warning-group" key={source}>
              <header><span>{source}</span><b>{items.length}</b></header>
              <div>
                {items.map((notice) => (
                  <article className={`warning-item warning-item--${notice.severity}`} key={notice.id}>
                    <span className="warning-item__icon">{notice.severity === "danger" ? <ShieldAlert size={17} /> : notice.severity === "info" ? <Info size={17} /> : <AlertTriangle size={17} />}</span>
                    <span><strong>{notice.title}</strong><p>{notice.detail}</p>{notice.context && <code>{notice.context}</code>}</span>
                    <StatusPill tone={notice.severity === "danger" ? "danger" : notice.severity === "warning" ? "warning" : "info"}>{notice.severity}</StatusPill>
                  </article>
                ))}
              </div>
            </section>
          ))}
        </Card>
      )}
    </div>
  );
}
