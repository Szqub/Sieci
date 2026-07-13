# Panorama Cleaner

Samodzielny projekt znajduje się w całości w katalogu `panorama_cleaner/`.
Przed uruchomieniem wejdź do tego katalogu; wejścia i katalogi wynikowe są
domyślnie rozwiązywane względem położenia skryptu.

**Entry point:** `panorama_cleanup_planner.py`

Narzędzie jest generatorem planu dla Panorama/PAN-OS 10.2.16-h4. Samo nie
zmienia konfiguracji i nigdy nie generuje `commit`. Dla całej listy IP:

1. równolegle wykonuje domyślny ICMP i pomija adresy, które odpowiadają;
2. przez XML API pobiera po jednym pełnym snapshotcie `running` (`action=show`)
   i `candidate` (`action=get`);
3. porównuje oba snapshoty i planuje na `running`; przy istotnym driftcie zapisuje
   tylko draft i **nie publikuje** stosowalnego `commands.txt`, bo CLI zmienia
   bieżący `candidate`;
4. lokalnie rozpoznaje prawdziwe nazwy obiektów po dokładnej wartości IP;
5. analizuje `shared`, wszystkie widoczne device groups, dziedziczenie,
   statyczne/zagnieżdżone grupy, override i globalną kolejność precedence oraz
   Security i NAT w pre/post-rulebase;
6. liczy jeden wsadowy plan, więc nigdy nie pozostawia pustego `source`,
   `destination` ani dotkniętej statycznej grupy;
7. zapisuje pełny XML każdej zmienianej lub usuwanej encji, rollback, raporty
   i manifest; stosowalny `commands.txt` jest zawsze ostatnim zapisem runu.

Rozpoznawane są hosty `ip-netmask`, singleton `ip-range` i exact
`ip-wildcard`; szersze podsieci, zakresy i wildcardy są raportowane wraz z ich
zależnościami, ale nigdy automatycznie usuwane. Szerszy literal w polityce lub
puli NAT blokuje całe IP. Obiektów FQDN skrypt nie przypisuje do IP na podstawie
chwilowego DNS — raportuje tę granicę jawnie i wstrzymuje publikację komend.
Referencje poza obsługiwanym
Security/NAT source/destination, zanegowane pola, cykle grup, niebezpieczny
fallback override i możliwe członkostwo w dynamic address group blokują całe
IP do ręcznego review. Pola translacji NAT domyślnie blokują;
całą regułę NAT można przeznaczyć do usunięcia wyłącznie przez jawne
`--nat-translation delete-rule`.

Ważna granica: operacyjne rejestracje IP→tag dla dynamic address groups nie są
częścią `running` ani `candidate`. Jeżeli w snapshotcie istnieje choć jedna DAG,
skrypt generuje statyczny raport i wyraźnie oznaczony draft, ale domyślnie
**wstrzymuje globalnie `commands.txt`** (`RUNTIME_DAG_MEMBERSHIP_UNVERIFIED`).
Nie wolno deklarować kompletnego cleanupu wyłącznie z tych dwóch snapshotów;
membership trzeba osobno zweryfikować na właściwych managed firewallach.
Analogicznie dowolny obiekt FQDN powoduje blokadę
`FQDN_RESOLUTION_UNVERIFIED`, ponieważ lokalny DNS nie jest autorytatywnym
stanem rozwiązania nazwy na firewallu. IP External Dynamic Lists, custom lub
predefined regions i nierozwiązane nazwy z pól adresowych również wstrzymują
`commands.txt`: ich zawartości albo namespace nie można kompletnie przypisać do
target IP z samych snapshotów. Poprawne surowe subnety, range i wildcardy są
modelowane per-IP i same nie uruchamiają tej globalnej blokady.

## Pliki wejściowe

Utwórz `panorama_host.txt` na podstawie `panorama_host.txt.example`:

```text
host=192.0.2.10
username=panorama-api-user
```

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

Weryfikacja TLS jest włączona. Dla wewnętrznego CA użyj
`--ca-bundle C:\sciezka\ca.pem`. `--insecure` istnieje wyłącznie jako jawny,
niezalecany wyjątek. Ochronny ICMP można pominąć tylko przez `--no-ping`.

Każdy run tworzy osobny katalog `run_DDMMYY_HH_MM_SS`, między innymi:

```text
commands.txt
rollback_commands.txt
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

Przy istotnej różnicy candidate zamiast `commands.txt` i
`rollback_commands.txt` powstają wyłącznie wyraźnie oznaczone pliki
`draft_*_BLOCKED_candidate_drift.txt`. Niepoprawny wiersz wejścia albo błąd
uruchomienia ICMP również wstrzymuje cały `commands.txt` i tworzy
`draft_*_BLOCKED_incomplete_input_or_icmp.txt` — skrypt nie publikuje planu dla
nieoznaczonego podzbioru. Nie wolno stosować żadnego draftu; trzeba usunąć
blokadę i uruchomić skrypt ponownie. Wszystkie globalne ostrzeżenia są widoczne
w `apply_readme.txt`, obu raportach, `manual_review.json` i manifeście.
Blokady DAG/FQDN/EDL/region/unmodeled namespace używają nazwy
`draft_*_BLOCKED_runtime_dependencies.txt`.

Nazwy backupów zawierają nazwę encji, timestamp `DDMMYY_HH_MM` i stabilny
skrót zapobiegający kolizjom. Raporty mówią „zaplanowano”, ponieważ żadna
komenda nie została wykonana. `rollback_commands.txt` odtwarza wartości i
pozycję reguł w candidate, natomiast pełne XML w `backups/` pozostają
autorytatywnym backupem (na przykład UUID reguły może wymagać kontrolowanego
`load config partial`/XML API).

Jeżeli running i candidate różnią się w obiektach, device groups lub rulebase,
proces kończy się kodem 2 i wstrzymuje `commands.txt`. Tak samo publikację
wstrzymuje nierozstrzygnięty runtime DAG; niepoprawne wejście lub błąd procesu
ICMP kończy się kodem 3. Po bezpiecznym ponownym runie administrator nadal
wykonuje `validate full` i `show config diff`; dopiero potem ręcznie decyduje o
commit.

Kody wyjścia: `0` — kompletny plan; `2` — plan z warningiem/review/pominiętym
ICMP; `3` — wejście lub ICMP; `4` — transport/snapshot; `5` — XML/scope;
`6` — backup/wyjście; `7` — naruszenie inwariantu.

Testy offline:

```powershell
python -m unittest discover -s tests -v
```
