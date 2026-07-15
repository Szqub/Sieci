# Walidacja laboratoryjna Panorama 10.2.16-h4

Wykonaj na nieprodukcyjnej device group i testowym firewallu. Zachowaj pełny
eksport konfiguracji poza Toolboxem. Nie przechodź do następnego etapu, jeśli
bieżący nie ma jednoznacznego wyniku.

## 1. Read-only i plan

1. Ustaw `api_max_stage=read-only`.
2. Uruchom `doctor --api-check` i cleanup plan dla dwóch testowych IP.
3. Potwierdź dokładnie dwa snapshoty (`running`, `candidate`), poprawny
   `change-summary`, zależności shared/DG oraz pre/post security, NAT i
   application-override.
4. Wprowadź niezależną zmianę poza dotkniętymi XPath i potwierdź, że jest tylko
   informacją.
5. Wprowadź zmianę na dotkniętej encji i potwierdź konflikt wyłącznie jej
   komponentu.

## 2. Candidate apply i rollback

1. Ustaw `api_max_stage=candidate`; włącz zapis jawnie.
2. Potwierdź pozyskanie właściwych config locków, zapis `pre_running.xml`,
   `pre_candidate.xml`, SHA256 i backupów encji przed pierwszą mutacją.
3. Zastosuj testowy PatchSet bez commit i porównaj candidate z planem.
4. Wymuś błąd w środku następnego batcha. Potwierdź inverse operations w
   odwrotnej kolejności oraz zgodność końcowego candidate z precondition.
5. Wymuś timeout odpowiedzi mutującego POST. Potwierdź brak retry i stan
   `OUTCOME_UNKNOWN`; rozstrzygnij ręcznie aktualny candidate.
6. Po utworzeniu planu dodaj w candidate nową politykę lub grupę odwołującą się
   do celu. Apply ma wykryć zmianę w ponownym planie i pominąć cały zależny
   komponent.
7. Wymuś błąd rollbacku. Potwierdź `OUTCOME_UNKNOWN`, zachowany config lock i
   marker blokujący następny candidate apply/commit/push.
8. Przerwij `Ctrl+C` po wysłaniu mutacji oraz podczas pollingu commit/push.
   Potwierdź `OUTCOME_UNKNOWN`, zachowane config locki i marker wymagający
   ręcznego reconciliation.

## 3. Commit

1. Ustaw `api_max_stage=commit`.
2. Potwierdź, że bez `--allow-unisolated-commit` request nie jest wysyłany.
3. Wykonaj partial commit testowego administratora i śledź job do `FIN/OK`.
4. Sprawdź manifest joba, ryzyko same-admin i `post_running.xml`.
5. Full commit testuj wyłącznie na czystym labie, z obiema jawnymi flagami.

## 4. Push

1. Ustaw `api_max_stage=push`.
2. Zmień encję w parent DG i potwierdź, że lista obejmuje także właściwe child
   DG, ponieważ XML API nie propaguje ich automatycznie.
3. Potwierdź `include-template=no`, sekwencyjny pojedynczy job batcha oraz
   wynik dla każdego urządzenia/VSYS widoczny w szczegółach joba.
4. Wymuś częściowy błąd managed firewall i potwierdź, że sesja nie otrzymuje
   globalnego `PUSHED`.

## 5. Three-way Emergency Restore

1. Po cleanup dodaj niezależny obiekt/członka poza dotkniętymi XPath.
2. Utwórz restore po jednym IP. Potwierdź, że obejmuje tylko przechodni
   komponent tego IP, nie cały pierwotny batch.
3. Zastosuj restore candidate. Potwierdź zachowanie później dodanych członków.
4. Dla polityki sprawdź historyczną pozycję względem anchorów oraz DROP.
5. Sprawdź, czy Panorama zachowała historyczny UUID reguły. Jeśli nie, oznacz
   ograniczenie w runbooku i nie deklaruj restore 1:1 UUID.
6. Zmień tę samą encję po cleanup i potwierdź konflikt komponentu oraz ręczny
   pakiet XML/CLI, bez nadpisania zmiany.
7. Powtórz dla cleanup tylko w candidate oraz po commit/push.
8. W dwóch osobnych cleanupach usuń najpierw członka grupy/polityki, a później
   całą tę grupę/politykę. Restore po IP ma wskazać obie sesje źródłowe,
   odtworzyć encję przed członkiem i zakończyć z XML oraz pozycją reguły 1:1.
9. Pomiędzy restore plan i apply dodaj albo przesuń inną regułę w tym samym
   rulebase. Candidate apply ma pominąć cały komponent polityki jako konflikt,
   pozostawiając niezależne komponenty bez zmian.
10. Zmień parent DG wyłącznie w candidate. Restore ma wykryć różnicę resolution
    chain mimo niezmienionego running i nie może opublikować mutacji komponentu.
11. Przy `ancestor-objects-take-precedence=yes` dodaj w parent DG address o tej
    samej nazwie co odtwarzana child address-group. Restore ma wykryć zmianę
    końcowego `resolve_name` i wygenerować konflikt zamiast polityki o innej
    semantyce.

## Kryterium dopuszczenia

Profil write można dopuścić dopiero po zaliczeniu wszystkich używanych etapów,
archiwizacji manifestów i ręcznym potwierdzeniu na running/candidate, że
niezależna zmiana pozostała zachowana.
