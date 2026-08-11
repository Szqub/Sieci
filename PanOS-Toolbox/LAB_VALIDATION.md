# Walidacja laboratoryjna Panorama 10.2.16-h4

Wykonaj na nieprodukcyjnej device group i testowym firewallu. Zachowaj pełny
eksport konfiguracji poza Toolboxem. Nie przechodź do następnego etapu, jeśli
bieżący nie ma jednoznacznego wyniku.

## 0. Magazyn lokalny i telemetryka SMB

1. Na stacji z przekierowanym folderem Dokumenty uruchom `start_toolbox.cmd doctor` i potwierdź `Session Storage Local: PASS` oraz ścieżkę pod
   `%LOCALAPPDATA%\PanOS Toolbox`.
2. Potwierdź w **Backup i restore**, że wcześniejsze sesje z
   `Dokumenty\PanOS Toolbox` zostały skopiowane i są wyszukiwalne, a katalog
   źródłowy nie został zmodyfikowany ani usunięty.
3. Wykonaj lokalny plan bez WRITE. W nowej sesji journal ma być pojedynczym
   `journal\events.jsonl`; nie mogą powstawać kolejne `000001.json`,
   `000002.json` ani tymczasowe odpowiedniki tych nazw.
4. Jeżeli paczka leży na SMB, potwierdź brak nowych `__pycache__` i `.pyc` obok
   kodu. Telemetria udziału może zawierać odczyty/import starych sesji, ale nie
   może zawierać `SMB MOVE/RENAME` wykonanych przez Toolbox.
5. Powtórz pobranie do lokalnego katalogu. Jeżeli **Pobrane** jest na SMB,
   oddziel ewentualny rename przeglądarki z procesu pobierania od operacji
   wykonywanych po starcie Toolboxa.
6. Nie wyłączaj NDR/EDR i nie zmieniaj rozszerzeń. Każdy kolejny alert zachowaj
   z pełną ścieżką, nazwą detekcji, czasem, użytkownikiem i operacją SMB.

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

## 1A. Hand Mode na Panorama 10.2

1. Dla testowego batcha 300 polityk potwierdź, że aktywny plik ma dokładnie
   wszystkie unikalne linie `delete device-group ... rules ...`, bez JSON,
   `xpath=`, XML API, `configure`, `commit` i `push`.
2. Wybierz trzy nieprodukcyjne reguły. W CLI wykonaj `set cli scripting-mode
   on`, przejdź do `configure`, wklej aktywny plik i sprawdź `show | compare`.
   Diff musi odpowiadać 1:1 operacjom aktywnego PatchSetu. Nie commituj w tej
   próbie, jeżeli zakres nie jest dokładnie zgodny.
3. Powtórz dla tworzenia: address host/network, address-group z kilkoma
   memberami, service TCP/UDP, security policy z from/to/source/destination,
   application/service/tag/description oraz `move before/after/top/bottom`.
4. Użyj nazw zawierających spacje, apostrof i cudzysłów. Potwierdź poprawne
   quoting w CLI. Wstrzyknij znak nowej linii do opisu w kontrolowanym teście:
   status musi być `BLOCK`, a aktywny plik pusty — bez częściowych komend.
5. Wyklucz jedną regułę, komponent zależności oraz cel chroniony przez
   `DEFAULT`. `commands.txt` nie może ich zawierać; mają wystąpić wyłącznie w
   `handmode_excluded_commands.txt` z dodatkowym ostrzeżeniem GUI.
6. Otwórz sesję utworzoną starszą wersją i użyj **Wygeneruj Hand Mode
   offline**. Potwierdź brak połączeń do Panoramy, zachowanie starego
   `commands.txt` bez zmiany SHA oraz utworzenie `handmode_commands.txt`.
   Drugie kliknięcie nie może tworzyć kolejnej kopii plików.
7. Dla Restore potwierdź kolejność inverse operations: encja przed memberem,
   odtworzenie polityki i jej pozycji. Konfliktowy komponent ma być wyłącznie
   w `handmode_conflict_restore_commands.txt`, nigdy w bezpiecznym pliku.
8. Dla Custom LDAP Group zweryfikuj na PAN-OS 10.2 składnię `set template
   ... config vsys ... group-mapping ... custom-group ... ldap-filter ...` i
   odpowiadający rollback `delete`. Dwa bloki filtra muszą utworzyć dwie
   osobne nazwy `AD__NAZWA__01` i `AD__NAZWA__02`.
9. Po każdej próbie rollback wklej osobno, wykonaj `show | compare` i
   potwierdź powrót candidate do stanu początkowego. Commit/push pozostają
   osobnymi testami z kolejnych sekcji.

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
9. Po poprawnym Candidate otwórz **Pełny przegląd przed Commit**. Potwierdź,
   że pełny diff, lista zmian i `scope_guard` są zgodne z PatchSetem oraz że
   każdy artefakt ma niezależne akcje Wyświetl/Pobierz.
10. Dodaj do live candidate niezależną zmianę poza planem. Odśwież diff i
    potwierdź `CANDIDATE_OUTSIDE_PATCHSET` oraz zablokowany Commit.
11. Utwórz obcą politykę lub grupę nadal wskazującą usuwany adres/grupę.
    Potwierdź `RESIDUAL_REFERENCE` z nazwą właściciela, polem i XPath.

## 3. Commit

1. Ustaw `api_max_stage=commit`.
2. Potwierdź, że bez `--allow-unisolated-commit` request nie jest wysyłany.
3. Potwierdź, że podczas preflightu GUI jawnie pokazuje brak wysłanego joba, a
   Panorama nie ma jeszcze nowego job ID.
4. Wykonaj partial commit testowego administratora i śledź job od momentu
   nadania ID aż do `FIN/OK`.
5. Sprawdź manifest joba, ryzyko same-admin, ostatni scope guard i zgodność
   SHA live candidate z przeglądem. Po `FIN/OK` GUI ma natychmiast zakończyć
   etap, bez oczekiwania na blokujący pełny odczyt running.
6. Potwierdź w logu wydajności jeden pełny odczyt candidate. Jeżeli PAN-OS nie
   obsługuje `change-summary`, dozwolony jest drugi, jawnie opisany odczyt
   running jako fallback.
7. Full commit testuj wyłącznie na czystym labie, z obiema jawnymi flagami.

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
