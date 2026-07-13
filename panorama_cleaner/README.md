# Panorama Cleaner

Samodzielny projekt znajduje się w całości w katalogu `panorama_cleaner/`.
Przed uruchomieniem wejdź do tego katalogu; wejścia i katalogi wynikowe są
domyślnie rozwiązywane względem położenia skryptu.

**Entry point:** `panorama_cleanup_planner.py`

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
8. zapisuje pełny XML każdej zmienianej lub usuwanej encji, rollback, raporty
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
`show system info`, więc poza uwierzytelnieniem wykonuje dokładnie dwa odczyty
snapshotów konfiguracji.

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
można pominąć tylko przez `--no-ping`.

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
targetowane blokady nadal pomijają wyłącznie ryzykowne IP. Niepoprawny wiersz
wejścia albo błąd uruchomienia ICMP wstrzymuje cały `commands.txt` i tworzy
`draft_*_BLOCKED_incomplete_input_or_icmp.txt` — skrypt nie publikuje planu dla
nieoznaczonego podzbioru. Nie wolno stosować żadnego draftu; trzeba usunąć
blokadę i uruchomić skrypt ponownie. Wszystkie globalne ostrzeżenia są widoczne
w `apply_readme.txt`, obu raportach, `manual_review.json` i manifeście.

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
administratora, niepoprawne wejście lub błąd procesu ICMP; te przypadki kończą
się kodem 3. Po bezpiecznym runie administrator nadal
wykonuje `validate full` i ponownie `show config diff`; dopiero potem ręcznie
decyduje o commit.

Kody wyjścia: `0` — kompletny plan; `2` — plan z warningiem/review/pominiętym
ICMP; `3` — wejście lub ICMP; `4` — transport/snapshot; `5` — XML/scope;
`6` — backup/wyjście; `7` — naruszenie inwariantu.

Testy offline:

```powershell
python -m unittest discover -s tests -v
```
