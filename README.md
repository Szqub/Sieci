# Dokumentacja Skryptów Automatyzacji Sieciowej

To repozytorium zawiera zestaw zaawansowanych skryptów do zarządzania, weryfikacji i czyszczenia konfiguracji w środowiskach sieciowych, ze szczególnym naciskiem na **Palo Alto Networks Panorama**.

Poniżej znajduje się szczegółowa dokumentacja każdego narzędzia, opisująca jego logikę działania, wymagania oraz sposób użycia.

## 0. Wsadowe czyszczenie obiektów Panoramy (nowe)

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

### Pliki wejściowe

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

### Hasło

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

### Uruchomienie

Python 3.9+ i zależność `requests`:

```powershell
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

---

## Spis Treści

0. [Wsadowe czyszczenie obiektów Panoramy](#0-wsadowe-czyszczenie-obiektów-panoramy-nowe)
1. [Weryfikacja Hostów (Panorama Group Checker)](#1-weryfikacja-hostów-panorama-group-checker)
2. [Wyszukiwarka Reguł (Panorama Rule Finder)](#2-wyszukiwarka-reguł-panorama-rule-finder)
3. [Analiza Hit Count (Panorama Rules Checker)](#3-analiza-hit-count-panorama-rules-checker)
4. [Czyszczenie Obiektów (Panorama Object Cleanup)](#4-czyszczenie-obiektów-panorama-object-cleanup)
5. [Masowe Wyłączanie Reguł (Disable Commands Generator)](#5-masowe-wyłączanie-reguł-disable-commands-generator)
6. [Diagnostyka Illumio (Illumio Probe)](#6-diagnostyka-illumio-illumio-probe)
7. [Generator Filtrów AD (AD Group Generator)](#7-generator-filtrów-ad-ad-group-generator)

---

## 1. Weryfikacja Hostów (Panorama Group Checker)

**Główny skrypt:** `panorama_group_checker_update` (oraz starsza wersja `Panorama_group_checker_v2`)

### Cel
Kompleksowa weryfikacja zgodności bazy adresowej (CMDB/Excel) z rzeczywistą konfiguracją w Panoramie. Skrypt sprawdza, czy dany host istnieje jako obiekt, czy jest w odpowiedniej grupie i czy nie ma "martwych dusz" w grupach.

### Jak to działa?
1.  **Pobieranie danych**: Łączy się z API Panoramy (XML API) i pobiera **wszystkie** obiekty adresowe oraz grupy adresowe (zarówno z konkretnych `device-group`, jak i `shared`).
2.  **Parsowanie**: Przetwarza XML na wewnętrzne struktury danych (słowniki Python), identyfikując obiekty typu `ip-netmask` oraz `ip-range`.
3.  **Analiza wejścia**: Przyjmuje listę hostów w formacie `nazwahosta-grupa IP`.
    *   Wyciąga "prefiks grupy" (np. z `srv-gr100` wyciąga `gr1`).
    *   Prosi użytkownika o zmapowanie tych prefiksów na rzeczywiste nazwy grup w Panoramie.
4.  **Weryfikacja logiczna**:
    *   **Bezpośrednie dopasowanie**: Czy istnieje obiekt `H-<IP>-32` i czy jest członkiem grupy?
    *   **Dopasowanie zakresowe**: Jeśli brak obiektu hosta, sprawdza czy IP mieści się w jakimkolwiek obiekcie `Range` (np. `R-10.0.0.1-50`), który należy do grupy.
5.  **Wykrywanie nadmiarowości**: Analizuje grupy w Panoramie i raportuje adresy IP, które są w konfiguracji, ale NIE było ich w pliku wejściowym (potencjalne stare obiekty do usunięcia).

### Użycie
```bash
python3 panorama_group_checker_update
```
Skrypt poprosi o:
*   Dane logowania do Panoramy.
*   Wybór metody wprowadzania danych (plik txt lub wpisywanie ręczne).
*   Mapowanie wykrytych prefiksów grup na grupy w Panoramie.

**Format pliku wejściowego:**
```text
serwer-web-gr1 192.168.1.10
baza-danych-gr2 10.0.0.5
```

---

## 2. Wyszukiwarka Reguł (Panorama Rule Finder)

**Skrypt:** `Panorama_Rule_Finder`

### Cel
Szybkie znalezienie wszystkich reguł bezpieczeństwa (Security Rules), w których użyty jest dany adres IP, bez konieczności przeklikiwania się przez GUI.

### Jak to działa?
1.  Łączy się przez **SSH** (biblioteka `paramiko`) do Panoramy.
2.  Ustawia format wyjścia CLI na `set` (`set cli config-output-format set`), co ułatwia parsowanie.
3.  Wykonuje polecenie `show | match <IP>`.
4.  Analizuje wynik, wyciągając nazwę `device-group` oraz nazwę reguły.
5.  Dla każdego trafienia pobiera szczegóły reguły (`show device-group X security rules Y`).

### Użycie
```bash
python3 Panorama_Rule_Finder
```
*   Podaj IP.
*   Wybierz kierunek (Source / Destination).
*   Skrypt wypisze listę znalezionych reguł wraz z ich parametrami.

---

## 3. Analiza Hit Count (Panorama Rules Checker)

**Skrypt:** `Panorama_rules_checker.py`

### Cel
Identyfikacja nieużywanych reguł (tzw. "shadow rules" lub reguł martwych) poprzez sprawdzenie licznika trafień (Hit Count).

### Jak to działa?
1.  Łączy się przez **SSH** (biblioteka `netmiko`).
2.  Pobiera listę `Device Groups` i prosi o wybór jednej.
3.  Prosi o wybór bazy reguł (`pre-rulebase` lub `post-rulebase`).
4.  Wczytuje listę nazw reguł z pliku tekstowego.
5.  Dla każdej reguły wykonuje komendę:
    `show rule-hit-count device-group <DG> <BASE> security rules rule-name <NAME>`
6.  Sumuje liczniki trafień ze wszystkich podłączonych firewalli.

### Wynik
Generuje trzy pliki:
*   `rules_0hit`: Reguły z licznikiem 0 (kandydaci do usunięcia).
*   `rules_hit`: Reguły aktywne.
*   `rules_not_found`: Reguły, których nie znaleziono (np. literówka w nazwie).

### Użycie
```bash
python3 Panorama_rules_checker.py
```

---

## 4. Czyszczenie Obiektów (Panorama Object Cleanup)

**Skrypt:** `Panorama_object_cleanup.py` (wrapper: `panorama_object_cleaner`)

### Cel
Bezpieczne usuwanie obiektów adresowych. W Panoramie nie można usunąć obiektu, jeśli jest używany w regule lub grupie. Ten skrypt generuje sekwencję poleceń, aby najpierw "uwolnić" obiekt, a potem go usunąć.

### Jak to działa?
1.  **Pół-automatyka**: Skrypt nie wykonuje zmian sam (dla bezpieczeństwa). Działa jako asystent.
2.  Prosi użytkownika o wykonanie w CLI komendy `show | match H-IP-32` i wklejenie wyniku.
3.  Analizuje wklejony tekst (format `set`) i wykrywa zależności:
    *   Czy obiekt jest w `source` lub `destination` reguły?
    *   Czy jest członkiem `address-group`?
4.  **Generowanie komend**: Tworzy listę poleceń `delete ...`, które precyzyjnie usuwają tylko ten obiekt z grup i reguł.
    *   Jeśli obiekt jest jedynym elementem w regule, skrypt zaproponuje usunięcie całej reguły (w sekcji `delete_policies`).

### Użycie
```bash
python3 Panorama_object_cleanup.py --ip-file lista_ip.txt
# lub interaktywnie bez argumentów
```

---

## 5. Masowe Wyłączanie Reguł (Disable Commands Generator)

**Skrypt:** `generate_disable_commands.py`

### Cel
Szybkie wygenerowanie skryptu CLI do wyłączenia dużej liczby reguł (np. po analizie Hit Count).

### Jak to działa?
1.  Pobiera nazwę `Device Group` i typ `Rulebase`.
2.  Wczytuje plik z nazwami reguł.
3.  Tworzy polecenia w formacie:
    `set device-group <DG> <BASE>-rulebase security rules "<NAZWA>" disabled yes`
4.  Zapisuje wynik do pliku `rules_disable_cli_pa.txt`, dzieląc go na bloki po 30 komend (aby nie przeciążyć bufora CLI przy wklejaniu).

### Użycie
```bash
python3 generate_disable_commands.py
```

---

## 6. Diagnostyka Illumio (Illumio Probe)

**Plik:** `Ilumio_API` (zawiera skrypt Bash `illumio_probe.sh`)

### Cel
Szybki "health check" i pobranie statystyk ze środowiska Illumio PCE (Policy Compute Engine) bez logowania do GUI.

### Jak to działa?
1.  Używa `curl` do komunikacji z REST API Illumio.
2.  Wymaga `jq` do parsowania JSON.
3.  Sprawdza endpointy:
    *   `/api/v2/product_version` (wersja softu).
    *   `/api/v2/orgs/1/labels` (liczba labeli).
    *   `/api/v2/orgs/1/workloads` (liczba serwerów/agentów).
    *   `/api/v2/orgs/1/container_clusters` (klastry K8s/OpenShift).

### Użycie
```bash
# Edytuj plik i wpisz KEY/TOKEN lub podaj je przy uruchomieniu:
KEY="api_key_id" TOKEN="api_key_secret" ./illumio_probe.sh
```

---

## 7. Generator Filtrów AD (AD Group Generator)

**Skrypt:** `pa_ad_group_generator.ps1`

### Cel
Automatyzacja tworzenia filtrów LDAP dla mapowania grup Active Directory w Palo Alto (User-ID Group Mapping). Palo Alto często wymaga filtrów w formacie `(|(memberof=CN=...)(memberof=CN=...))`.

### Jak to działa?
1.  Wczytuje nazwy grup z pliku `ad_groups.txt`.
2.  Używa modułu PowerShell `ActiveDirectory` (`Get-ADGroup`), aby pobrać pełny `DistinguishedName` (DN) każdej grupy.
3.  Weryfikuje, czy grupa nie jest pusta (pomija puste, aby nie zapychać konfiguracji).
4.  Grupuje wyniki w bloki po 6 (ograniczenie długości filtra lub czytelność).
5.  Generuje gotowy string filtra LDAP.

### Użycie
1.  Uzupełnij plik `ad_groups.txt`.
2.  Uruchom w PowerShell z uprawnieniami do AD (RSAT):
```powershell
.\pa_ad_group_generator.ps1
```
