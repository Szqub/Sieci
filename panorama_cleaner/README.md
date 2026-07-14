# Panorama Cleaner

Samodzielny projekt znajduje się w całości w katalogu `panorama_cleaner/`.
Przed uruchomieniem wejdź do tego katalogu; wejścia i katalogi wynikowe są
domyślnie rozwiązywane względem położenia skryptu.

**Entry point planera:** `panorama_cleanup_planner.py`

**Entry point audytu po czyszczeniu:** `panorama_post_cleanup_audit.py`

**Entry point awaryjnego restore per IP:** `panorama_emergency_restore.py`

Narzędzie jest generatorem planu dla Panorama/PAN-OS 10.2.16-h4. Samo nie
zmienia konfiguracji i nigdy nie generuje `commit`. Dla całej listy IP:

1. wymaga wpisania dokładnie `TAK`, którym administrator potwierdza wcześniejsze
   sprawdzenie diffu running/candidate bezpośrednio w Panoramie;
2. równolegle wykonuje domyślny ICMP i pomija adresy, które odpowiadają;
3. przez XML API pobiera po jednym pełnym snapshotcie `running` (`action=show`)
   i `candidate` (`action=get`), ale nie porównuje ich automatycznie;
4. planuje wyłącznie na podstawie `running`;
5. lokalnie rozpoznaje prawdziwe nazwy obiektów po dokładnej wartości IP;
6. analizuje `shared`, wszystkie widoczne device groups, dziedziczenie,
   statyczne/zagnieżdżone grupy, override i globalną kolejność precedence oraz
   Security, NAT i Application Override w pre/post-rulebase;
7. liczy jeden wsadowy plan, więc nigdy nie pozostawia pustego `source`,
   `destination` ani dotkniętej statycznej grupy;
8. dla polityk przeznaczonych do pełnego usunięcia pobiera operacyjny
   `rule-hit-count` i klasyfikuje `last-hit` względem 14 dni;
9. zapisuje pełny XML każdej zmienianej lub usuwanej encji, rollback, raporty
   i manifest; stosowalny `commands.txt` jest zawsze ostatnim zapisem runu.

Rozpoznawane są hosty `ip-netmask`, singleton `ip-range` i exact
`ip-wildcard`; szersze podsieci, zakresy i wildcardy są raportowane wraz z ich
zależnościami, ale nigdy automatycznie usuwane. Szerszy literal w polityce lub
puli NAT blokuje całe IP. Obiektów FQDN skrypt nie przypisuje do IP na podstawie
chwilowego DNS — raportuje tę granicę jawnie, ale samo istnienie niezwiązanego
FQDN nie blokuje usunięcia nazwanego address object. Referencje poza obsługiwanym
Security/NAT/Application Override source/destination, zanegowane pola, cykle
grup, niebezpieczny fallback override i możliwe członkostwo w dynamic address
group blokują całe IP do ręcznego review. Bezpośrednia dokładna referencja w
polu translacji NAT domyślnie przeznacza całą regułę NAT do usunięcia, ponieważ
pozostawienie reguły bez wymaganej translacji byłoby niebezpieczne. To samo
dotyczy referencji do grupy, która po czyszczeniu stałaby się pusta i zostanie
usunięta. Jeżeli translacja wskazuje grupę pozostającą niepustą, skrypt usuwa
z niej target, ale zachowuje regułę NAT dla pozostałych członków. Zachowawczy
tryb `--nat-translation block` zamiast tego wymusza manual review. Szersze
pule, zakresy i podsieci translacji nadal blokują target i nie są automatycznie
modyfikowane.

Ważna granica zakresu: plan dotyczy zależności nazwanych obiektów widocznych w
running config. Operacyjne rejestracje IP→tag dla DAG, rozwiązania FQDN, runtime
contents IP EDL i predefined regions nie są częścią `running` ani `candidate`.
Ich sama obecność jest raportowana jako warning i daje kod wyjścia `2`, ale nie
blokuje globalnie `commands.txt`, ponieważ nie jest referencją do usuwanej
definicji address object. Planner nadal blokuje targetowo obiekt z tagami
pasującymi do filtra DAG, dotkniętą grupę z nierozwiązanym członkiem oraz każdą
rozpoznaną zależność NAT/polityki. Jeżeli celem jest potwierdzenie, że IP nie
występuje również semantycznie przez runtime DAG/FQDN/EDL/region, administrator
musi wykonać osobny audit na właściwych managed firewallach. Skrypt nie może
uczciwie dowieść tego z dwóch snapshotów konfiguracji.

## Pliki wejściowe

Utwórz `panorama_host.txt` na podstawie `panorama_host.txt.example`:

```text
host=192.0.2.10
username=panorama-api-user
ssl=yes
```

`ssl=yes` weryfikuje certyfikat TLS. `ssl=no` nadal używa szyfrowanego HTTPS,
ale wyłącza weryfikację certyfikatu i zastępuje konieczność podawania
`--insecure`. Brak pola `ssl` zachowuje bezpieczną wartość domyślną `yes`.

Hasła nie wolno wpisywać do tego pliku. `ip.txt` zawiera jeden adres IPv4 lub
IPv6 na linię; puste linie i linie zaczynające się od `#` są ignorowane.

Konto API musi mieć pełny odczyt konfiguracji `shared` i wszystkich device
groups objętych czyszczeniem. Skrypt może zagwarantować kompletność wyłącznie
dla konfiguracji widocznej temu kontu; ograniczony RBAC jest blockerem
operacyjnym i nie wolno wtedy stosować komend. Skrypt nie odpytuje osobno
`show system info`. Zawsze wykonuje dokładnie dwa odczyty konfiguracji, a
dodatkowo po jednym szczegółowym operacyjnym `show rule-hit-count ... rules
rule-name` dla każdej polityki przeznaczonej do pełnego usunięcia. Panorama nie
zwraca szczegółowego `last-hit-timestamp` dla wielu nazw przez firewallowe
`rules list`, dlatego odczyty są wykonywane per reguła.

## Hasło

Dokładna domyślna nazwa zmiennej to `PANORAMA_PASSWORD`. Najbezpieczniej
pozwolić skryptowi zapytać o hasło przez ukryty prompt. Dla automatyzacji w
bieżącej sesji PowerShell 7:

```powershell
$env:PANORAMA_PASSWORD = Read-Host "Hasło Panoramy" -MaskInput
python .\panorama_cleanup_planner.py
Remove-Item Env:PANORAMA_PASSWORD
```

Inną nazwę można wskazać przez `--password-env NAZWA`. Nie używaj `setx` do
hasła: zapisuje je trwale jako tekst jawny w profilu użytkownika.
Procesy `ping` otrzymują jawnie oczyszczone środowisko bez wskazanej zmiennej
hasła.

## Potwierdzenie diffu

Automatyczne porównanie running/candidate jest wyłączone. Każdy run przed ICMP
i połączeniem z Panoramą wymaga wpisania dokładnie `TAK`. Potwierdzenie oznacza,
że administrator sprawdził wcześniej diff w GUI/CLI Panoramy, nie ma
oczekujących zmian, akceptuje zakres zależności nazwanych address objects z
running config i świadomie chce kontynuować. Runtime DAG/FQDN/EDL/region nie
jest audytowany przez ten run. Brak potwierdzenia przerywa run kodem 3. Oba
snapshoty nadal są pobierane; plan zawsze powstaje z running.

## Uruchomienie

Python 3.9+ i zależność `requests`:

```powershell
Set-Location .\panorama_cleaner
python -m pip install -r requirements.txt
python .\panorama_cleanup_planner.py `
  --host-file .\panorama_host.txt `
  --ip-file .\ip.txt `
  --output-dir .
```

Weryfikacją TLS steruje `ssl=yes/no` w `panorama_host.txt`. Dla wewnętrznego
CA ustaw `ssl=yes` i użyj `--ca-bundle C:\sciezka\ca.pem`. `--insecure`
pozostaje wyłącznie jako zgodnościowy, niezalecany override. Ochronny ICMP
można pominąć tylko przez `--no-ping`. Lokalny błąd uruchomienia procesu
`ping` jest domyślnie ponawiany dwa razy (łącznie maksymalnie trzy próby).
Liczbę ponowień można ustawić w zakresie `0..5` przez
`--ping-error-retries N`; ponawiane są wyłącznie wyniki `ERROR`, nigdy zwykły
brak odpowiedzi hosta.

Każdy run tworzy osobny katalog `run_DDMMYY_HH_MM_SS`, między innymi:

```text
commands.txt
rollback_commands.txt
rollback_manual_restore_required.txt  # tylko gdy rollback CLI jest niepełny
apply_readme.txt
raport_krotki.txt
raport_szczegolowy.txt
input_status.csv
icmp_responded.txt
icmp_no_response.txt
icmp_errors.txt
policy_last_hit_all.csv
policies_recent_hits_review.txt
policies_no_last_hit_review.txt
policies_last_hit_ok.txt
policies_hit_count_errors.txt
candidate_comparison.json
manual_review.json
manifest.json
backups/objects/...
backups/groups/...
backups/policies/...
```

`candidate_comparison.json` zapisuje, że automatyczny diff był pominięty oraz
że administrator go potwierdził. Ostrzeżenia o obecności DAG/FQDN/EDL/region i
niewymodelowanych, niezwiązanych nazwach nie tworzą już globalnego draftu;
targetowane blokady nadal pomijają wyłącznie ryzykowne IP. Po wyczerpaniu
ponowień trwały `ERROR` ICMP pomija tylko konkretne IP i oznacza je jako
`ZABLOKOWANO_BŁĄD_ICMP`. Pozostały poprawnie sprawdzony podzbiór nadal trafia
do `commands.txt`, a szczegóły błędu są w `icmp_errors.txt`,
`input_status.csv`, raportach, `manual_review.json` i manifeście. Niepoprawny
wiersz wejścia nadal wstrzymuje cały `commands.txt` i tworzy
`draft_*_BLOCKED_incomplete_input.txt`, ponieważ plan obejmowałby
nieoznaczony podzbiór wejścia. Nie wolno stosować żadnego draftu; trzeba usunąć
blokadę i uruchomić skrypt ponownie.

Nazwy backupów zawierają nazwę encji, timestamp `DDMMYY_HH_MM` i stabilny
skrót zapobiegający kolizjom. Raporty mówią „zaplanowano”, ponieważ żadna
komenda nie została wykonana. `rollback_commands.txt` odtwarza wartości i
pozycję reguł w candidate. Jeżeli opis, komentarz albo inne pole zawiera znak
sterujący, którego nie można bezpiecznie wkleić do CLI, tylko ta pomocnicza
komenda rollbacku jest pomijana, a run tworzy
`rollback_manual_restore_required.txt`. Pełne XML w `backups/` pozostają
autorytatywnym backupem do kontrolowanego `load config partial`/XML API (dotyczy
to również atrybutów takich jak UUID).

Targetowane blokady bezpieczeństwa pomijają konkretne ryzykowne IP i są opisane
w raportach. Publikację całego `commands.txt` wstrzymuje brak potwierdzenia
administratora albo niepoprawne wejście; te przypadki kończą się kodem 3.
Trwały błąd procesu ICMP daje kod 2 i pomija wyłącznie wskazane IP. Po
bezpiecznym runie administrator nadal
wykonuje `validate full` i ponownie `show config diff`; dopiero potem ręcznie
decyduje o commit.

### Last-hit polityk usuwanych w całości

Odczyt jest wyłącznie pomocniczy i nie analizuje traffic logów. Dotyczy tylko
reguł, które plan zamierza usunąć w całości; reguły z usuwanym pojedynczym
członkiem nie są odpytane. `STALE` oznacza potwierdzony `last-hit` starszy niż
14 dni. `RECENT` (14 dni lub mniej), `NEVER`, `NOT_LATEST`, brak reguły i błąd
odczytu trafiają do review. `NEVER` nie jest automatycznie uznawany za bezpieczny,
bo bez czasu utworzenia/resetu licznika nie dowodzi pełnych 14 dni obserwacji.
Jeśli Panorama zwróci osobne obserwacje z kilku firewalli/VSYS, raport sumuje
`hit-count`, ale do klasyfikacji używa najnowszego `last-hit` ze wszystkich
obserwacji. Wystarczy więc jeden świeży hit na dowolnym urządzeniu, aby polityka
trafiła do `RECENT`.

Błąd lub świeży ruch nie blokuje publikacji: `commands.txt` nadal powstaje,
skrypt kończy się kodem `2`, a szczegóły trafiają do osobnych raportów.
Administrator decyduje, czy pominąć daną komendę lub wykonać dodatkową
weryfikację.

Kody wyjścia: `0` — kompletny plan; `2` — plan z warningiem/review/pominiętym
IP (w tym trwałym błędem ICMP); `3` — wejście; `4` — transport/snapshot;
`5` — XML/scope;
`6` — backup/wyjście; `7` — naruszenie inwariantu.

## Audyt po wykonaniu czyszczenia

`panorama_post_cleanup_audit.py` jest osobnym, wyłącznie odczytowym przebiegiem.
Nie prosi o potwierdzenie diffu, nie tworzy komend i nie zmienia Panoramy.
Korzysta z tych samych `panorama_host.txt`, `ip.txt`, ustawień hasła, TLS i ICMP
co planner. Pobiera dokładnie running (`action=show`) i candidate (`action=get`),
ale analizuje wyłącznie running; candidate jest pobrany tylko jako drugi snapshot
i nie jest porównywany.

Audyt ponownie sprawdza wszystkie IP. Adres odpowiadający na ICMP jest traktowany
jako oczekiwany do pozostawienia, ale raport nadal pokazuje jego dokładne obiekty,
scope/device group, grupy, reguły Security/NAT/Application Override,
pre/post-rulebase, pola translacji NAT i XPath. Dla braku odpowiedzi dokładny
pozostały obiekt, literal IP lub referencja po usuniętej nazwie daje alert.
Szersza podsieć, zakres albo wildcard zawierający IP jest raportowany osobno jako
review, a nie jako jednoznacznie pozostawiony obiekt hosta.

Najpełniejszy przebieg wymaga podania katalogu lub `manifest.json` z każdego runu,
którego komendy zastosowano:

```powershell
Set-Location .\panorama_cleaner
python .\panorama_post_cleanup_audit.py `
  --host-file .\panorama_host.txt `
  --ip-file .\ip.txt `
  --output-dir . `
  --previous-run .\run_140726_09_15_00 `
  --previous-run .\run_140726_10_30_00
```

Manifest zawiera powiązanie pierwotnego IP z nazwą i scope usuniętego obiektu.
Dzięki temu audyt może wykryć pozostawione `OLD_OBJECT` w grupie, polityce lub
translacji NAT nawet wtedy, gdy definicji `OLD_OBJECT` nie ma już w running.
Bez `--previous-run` nadal wykrywane są bieżące obiekty i bezpośrednie literały
IP, ale kompletności referencji po usuniętych nazwach nie da się dowieść;
audyt zapisze `HISTORIA_NIEPODANA` i zakończy się kodem `2`.

Każdy przebieg tworzy katalog `audit_DDMMYY_HH_MM_SS`:

```text
audit_summary.txt       # krótki wynik per LP/IP
audit_detailed.txt      # obiekty, zależności i dokładne ścieżki
audit_status.csv        # wynik tabelaryczny
audit_results.json      # pełne dane per IP
audit_manifest.json     # parametry, snapshoty, warningi i liczniki
icmp_responded.txt
icmp_no_response.txt
icmp_errors.txt
```

Nie powstają `commands.txt`, rollback ani backupy, ponieważ ten etap niczego nie
planuje ani nie usuwa. `0` oznacza brak alertów/review i pełną historię nazw;
`2` oznacza wykrytą pozostałość, wynik do review, błąd ICMP albo brak manifestów;
pozostałe kody `3`–`6` mają takie samo znaczenie jak w planerze.

Granice snapshotów pozostają takie same: runtime rejestracje DAG, bieżące
rozwiązania FQDN, runtime contents IP EDL oraz rozwinięcia regionów nie znajdują
się w running/candidate. Ich obecność jest jawnie raportowana; do semantycznego
potwierdzenia takich źródeł potrzebny jest osobny odczyt runtime na właściwych
managed firewallach.

## Awaryjny restore konkretnego IP

`panorama_emergency_restore.py` tworzy pakiet odtworzeniowy na podstawie
autorytatywnych XML i manifestów runów, których `commands.txt` faktycznie
zastosowano. Nie wykonuje ICMP, zmian, commit ani push. Przed połączeniem wymaga
wpisania `TAK`, potwierdzającego ręczne sprawdzenie diffu i pustego candidate.
Następnie pobiera running oraz candidate, ale analizuje running.

Podawaj runy jawnie — w kolejności nie ma znaczenia, bo decyduje ich
`started_utc`:

```powershell
Set-Location .\panorama_cleaner
python .\panorama_emergency_restore.py 10.0.0.1 `
  --host-file .\panorama_host.txt `
  --run .\run_140726_09_15_00 `
  --run .\run_140726_10_30_00 `
  --output-dir .
```

Kilka IP można podać pozycyjnie, wielokrotnym `--ip` albo przez `--ip-file`.
`--all-runs-applied --runs-dir .` włącza autodiscovery dopiero po jawnym
potwierdzeniu, że zastosowano każdy znaleziony run. Nie używaj tej opcji, jeżeli
w katalogu są plany wygenerowane, ale niewklejone.

Generator:

- weryfikuje SHA256 każdego backupu, zgodność `commands.txt` z manifestem,
  host Panoramy, `devices/entry`, device groups i historyczne dziedziczenie;
- od wskazanego IP buduje pełny połączony komponent zależności, na przykład
  `adres A → grupa G → inny usunięty adres B → grupa H → polityka P`;
- dla encji występującej w kilku runach odtwarza forward historię cleanup i
  odrzuca nieciągłość mogącą oznaczać zmianę administratora między paczkami;
- przywraca reguły według pełnej historycznej kolejności i najbliższego
  istniejącego anchoru; jeżeli pozycji 1:1 nie da się dowieść, zatrzymuje się
  zamiast przenosić regułę nad lub pod niewłaściwy DROP;
- akceptuje również znany stan częściowego rollbacku, więc może dokończyć
  odtwarzanie komponentu bez ponownego dodawania encji już zgodnych z backupem.

Powstaje katalog `restore_IP_DDMMYY_HH_MM_SS`:

```text
RESTORE_READY                       # obowiązkowy marker kompletnego pakietu
restore_report.txt                  # co i dlaczego wchodzi do domknięcia
restore_warnings.txt
restore_manifest.json               # źródła, SHA256 i dowód publikacji
restore_bundle.xml                  # pełne XML, w tym UUID
restore_commands.txt                # szybki wariant set/move CLI
restore_partial_load_commands.txt   # zalecany wariant XML 1:1
RESTORE_INSTRUCTIONS.txt
```

Nie używaj plików komend bez `RESTORE_READY`. Zalecana ścieżka importuje
`restore_bundle.xml` jako named configuration snapshot i wykonuje zapisane
`load config partial`: brakujące encje są mergowane z kontenerem nadrzędnym,
a istniejące znane stany częściowego rollbacku są zastępowane pełną wersją 1:1.
Po tym zawsze wykonaj `validate full` i `show config diff`; commit i push pozostają
ręczne. Szybki plik CLI odtwarza pola `set` i pozycję `move`, ale atrybutów
`entry`, takich jak UUID, nie odtworzy — do tego służy XML.

Ważne: Palo Alto opisuje, że `load config partial` z XPath na Panoramie może
zablokować selective push dla wszystkich device groups do czasu full commit/full
push. Przed użyciem XML zaplanuj wpływ na cały candidate i okno zmiany; zobacz
[KB Palo Alto o partial load na Panoramie](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000CrRyCAK).

Testy offline:

```powershell
python -m unittest discover -s tests -v
```
