# PanOS Toolbox

Lokalne GUI i CLI do analizy, generowania oraz kontrolowanego wykonywania
cleanup/restore na Panorama 10.2.16-h4. Serwer nasłuchuje wyłącznie na
`127.0.0.1`; frontend jest statyczny, więc Node.js nie jest wymagany na
maszynie docelowej.

Toolbox domyślnie jest **read-only/generator-only**. Zapis wymaga równocześnie:

1. odpowiedniego `api_max_stage` w CLI albo jawnego etapu wykonania w GUI;
2. jawnego `--enable-api-write` w CLI albo nietrwałego przełącznika w GUI.

Candidate, commit i push są osobnymi etapami. Żaden etap nie uruchamia
następnego automatycznie. Narzędzie nigdy automatycznie nie ładuje pełnego
backupu konfiguracji.

## Szybki start na maszynie docelowej

Wymagany jest Python 3.10+ i rozpakowana paczka zawierająca gotowy frontend.
Paczka release zawiera zależności webowe w `backend/vendor`: nie wymaga
Node.js, `pip install`, praw administratora ani lokalnego serwera IIS/Apache.

Pobierz asset ZIP z [najnowszego GitHub Release](https://github.com/Szqub/Sieci/releases/latest).
Checkout utworzony przez `git clone` jest kodem źródłowym i celowo nie zawiera
`backend/vendor`; na maszynie docelowej uruchamiaj wyłącznie paczkę portable.

Najprościej: wybierz w Eksploratorze **Wyodrębnij wszystkie**, wejdź do katalogu
`PanOS-Toolbox` i uruchom dwuklikiem `start_toolbox.cmd`. Launcher sprawdza
kompletność paczki i uruchamia Pythona z `-I -S`, więc globalny Flask nie jest
używany.

```powershell
Expand-Archive .\PanOS-Toolbox-YYYYMMDD-HHMMSS.zip -DestinationPath .\PanOS-Toolbox
Set-Location .\PanOS-Toolbox
Copy-Item .\panorama_host.txt.example .\panorama_host.txt
notepad .\panorama_host.txt
py -3 -I -S .\panos-toolbox.py doctor --host-file .\panorama_host.txt
.\start_toolbox.ps1 -Port 8765
```

Alternatywny launcher CMD oraz jego diagnostyka:

```powershell
.\start_toolbox.cmd
.\start_toolbox.cmd doctor
.\start_toolbox.cmd 9000
```

Następnie otwórz `http://127.0.0.1:8765/`. Serwera nie uruchamiaj z bindem
`0.0.0.0` ani na interfejsie sieciowym.

`start_toolbox.ps1` przekazuje domyślny `panorama_host.txt` jako sufit profilu
analitycznego i twardą granicę CLI. Brak pliku albo niedopasowanie hosta,
użytkownika lub TLS ustawia profil połączenia na `read-only`. Lokalny GUI ma
osobny, nietrwały grant wykonania opisany niżej; nadal wymaga zgodności hosta,
aktywnego connection tokenu, poprawnego Origin i jawnego przełącznika zapisu.

Nie instaluj Flask ani innych modułów globalnie. Paczka release ma przypięty
Flask i jego zależności w `backend/vendor`; tryb `-I -S` w poleceniu Doctor
potwierdza, że Toolbox nie korzysta z przypadkowych pakietów użytkownika.

## Cele cleanupu w GUI

Po połączeniu wpisz host, login i hasło w ekranie **Połączenie**, a następnie
przejdź do **Cleanup**. Edytor ma cztery niezależne zakładki i przyjmuje duże
listy wklejane z clipboardu lub z pliku `.txt`:

- **IP / literal** — adresy IP; opcjonalny ICMP kwalifikuje je do analizy;
- **Obiekty** — dokładne nazwy obiektów adresowych, po jednej w wierszu;
- **Grupy** — dokładne nazwy statycznych address groups, po jednej w wierszu;
- **Polityki** — dokładne nazwy reguł, po jednej w wierszu; spacje w nazwie są
  zachowywane.

Toolbox szuka wszystkich dokładnych trafień we wszystkich obsługiwanych
device groups, `shared`, pre/post-rulebase oraz typach Security, NAT i
Application Override. Dla polityki raportuje znaleziony DG/rulebase i pobiera
Last Hit przed wygenerowaniem operacji. Dla grupy najpierw planuje zdjęcie jej
z polityk oraz grup nadrzędnych, usuwa grupy opróżnione przez tę zmianę, a na
końcu wskazaną grupę. Dynamic address group jest raportowana jako blokada do
ręcznego review — nie jest automatycznie kasowana.

Analiza w GUI działa jako asynchroniczny job i pokazuje procentowy postęp dla
ICMP, pobierania running/candidate, grafu zależności, Last Hit oraz zapisu
artefaktów. Jeśli podano dokładnie jeden cel, Toolbox korzysta ze świeżego
snapshotu utworzonego podczas połączenia (maksymalnie 5 minut) i nie pobiera
ponownie pełnego configu. Po analizie przy każdym bezpiecznym celu jest przycisk
**Osobny plan**. Wydziela on cały powiązany komponent zależności do nowej sesji,
dzięki czemu obiekt, grupa lub polityka mogą być wykonane oddzielnie od batcha.

Application Override jest traktowany fail-closed. Bezpośrednio wskazana reguła
oraz każdy obiekt/grupa zależna od takiej reguły są oznaczone
`APP_OVERRIDE_READ_ONLY`, raportowane w GUI i wyłączane z automatycznych mutacji.
Chroni to batch przed zatrzymaniem na regule dziedziczonej albo read-only.

Kliknięcie **Analizuj zależności** niczego nie zapisuje. Wynikiem są: plan GUI,
komendy CLI, raport krótki, raport szczegółowy i manifest. Candidate, commit i
push pozostają trzema osobnymi, jawnymi etapami.

W sekcji **Wykonanie kontrolowane** GUI ma osobny, nietrwały wybór Candidate,
Commit albo Push. Jest on niezależny od profilu wybranego przy połączeniu i
działa wyłącznie razem z przełącznikiem **Zapis API** dla bieżącej sesji
przeglądarki. CLI nadal respektuje `api_max_stage` profilu.

## Generator Custom LDAP Group z Active Directory

Sekcja **Grupy AD** przenosi do GUI workflow ze skryptu
`pa_ad_group_generator.ps1`. Nie wymaga połączenia z Panorama. Przyjmuje dużą
listę nazw grup AD, nazwę wynikową, Device Template (opcjonalnie), nazwę Group
Mapping i VSYS. Domyślne miejsce docelowe to `LDAP_GM1` oraz `vsys1`.

Toolbox wykonuje lokalnie `Get-ADGroup -Properties Members` dla każdej
unikalnej nazwy. Do wyniku trafiają wyłącznie grupy, które istnieją i mają co
najmniej jednego bezpośredniego członka. Brakujące, puste oraz grupy z błędem
odczytu są pokazane osobno i pomijane. Distinguished Name jest zamieniany na
filtr `(memberof=...)`; filtry są grupowane operatorem OR po maksymalnie sześć
wpisów, tak jak w dotychczasowym skrypcie. Znaki specjalne wartości filtra są
escapowane zgodnie z RFC 4515.

Nazwa wynikowa zawsze otrzymuje kanoniczny prefiks `AD__`. Wpisanie `VPN_USERS`
da `AD__VPN_USERS`; istniejący prefiks nie zostanie zdublowany. GUI pokazuje
gotowe bloki i pozwala kopiować każdy osobno albo wszystkie naraz.

Walidacja wymaga Windows PowerShell i modułu `ActiveDirectory` z RSAT na stacji
uruchamiającej Toolbox. Paczka nie instaluje RSAT ani żadnego modułu globalnie.
Generator jest read-only: nie tworzy ani nie modyfikuje grup w AD i nie zapisuje
konfiguracji Panoramy. Bloki należy wkleić ręcznie w:

```text
Device Templates > [template] > User Identification > Group Mapping Settings
> LDAP_GM1 > Custom Group (VSYS: vsys1)
```

Automatyczny zapis tej sekcji przez XML API zostanie dodany dopiero po
potwierdzeniu dokładnego XPath i semantyki commit/push dla używanego template.

Test read-only API (keygen, running, candidate) jest opcjonalny:

```powershell
python .\panos-toolbox.py doctor --host-file .\panorama_host.txt --api-check
```

Hasło ani uzyskany przez keygen API key nie są zapisywane w profilu,
local/session storage, raportach ani logach; backend trzyma klucz wyłącznie w
pamięci procesu. Bez zmiennej środowiskowej CLI wyświetli ukryty prompt. W PowerShell 7
można ustawić je na czas bieżącej konsoli bez wyświetlania:

```powershell
$env:PANORAMA_PASSWORD = Read-Host -MaskInput "Hasło Panoramy"
python .\panos-toolbox.py cleanup plan --ip-file .\ip.txt
Remove-Item Env:PANORAMA_PASSWORD
```

Inną nazwę zmiennej wybiera `--password-env NAZWA`.

## Profil Panoramy

```text
host=10.0.0.1
username=superadmin
ssl=yes
verify_ssl=no
api_max_stage=read-only
```

- `ssl=yes` oznacza HTTPS, `ssl=no` oznacza jawny HTTP;
- `verify_ssl=yes` weryfikuje certyfikat HTTPS;
- `api_max_stage`: `read-only`, `candidate`, `commit` albo `push`;
- brak `api_max_stage` oznacza `read-only`.

`api_max_stage` pozostaje twardą granicą CLI. Lokalny GUI może wydać osobny,
godzinny lease wykonania dopiero po jednoczesnym włączeniu **Zapis API** i
wybraniu jawnego etapu w ekranie planu; lease jest przechowywany wyłącznie w
pamięci i jest związany z hostem bieżącego połączenia.

Kompatybilność: jeśli w starym profilu nie ma `verify_ssl`, Toolbox zachowuje
historyczne znaczenie `ssl` jako przełącznika weryfikacji certyfikatu i nadal
używa HTTPS. Nowe profile powinny zawsze zawierać oba pola.

## CLI

Plan niczego nie zapisuje w Panoramie:

```powershell
python .\panos-toolbox.py cleanup plan --ip-file .\ip.txt
python .\panos-toolbox.py cleanup plan --ip 10.0.0.10 --ip 10.0.0.11
python .\panos-toolbox.py cleanup plan --object "OLD-WEB-SERVER"
python .\panos-toolbox.py cleanup plan --group "GRP-LEGACY-SERVERS"
python .\panos-toolbox.py cleanup plan --policy "ALLOW LEGACY APP"
python .\panos-toolbox.py cleanup plan --ip 10.0.0.10 --object "OLD-WEB-SERVER" --group "GRP-LEGACY-SERVERS" --policy "ALLOW LEGACY APP"
```

Etapy zapisu wymagają profilu z odpowiednim limitem i jawnej flagi:

```powershell
python .\panos-toolbox.py cleanup apply --session SESSION_ID --enable-api-write
python .\panos-toolbox.py session commit --session SESSION_ID --enable-api-write --allow-unisolated-commit
python .\panos-toolbox.py session push --session SESSION_ID --enable-api-write --device-group DG1
```

Po `cleanup plan` skopiuj `session_id` z wyniku. Przed `apply`, `commit` i
`push` przejrzyj `commands.txt`, `raport_szczegolowy.txt`, ostrzeżenia Last Hit
oraz wyliczony zakres device groups. Nazwy przekazane przez `--object`,
`--group` i `--policy` są dokładne i każdą opcję można powtarzać.

Full commit jest osobnym, najwyższym ryzykiem:

```powershell
python .\panos-toolbox.py session commit --session SESSION_ID --enable-api-write --full --allow-full-commit
```

Emergency Restore można wyszukać po IP albo jawnej sesji:

```powershell
python .\panos-toolbox.py restore plan --ip 10.0.0.10
python .\panos-toolbox.py restore plan --source-session SESSION_ID
python .\panos-toolbox.py restore apply --session RESTORE_SESSION_ID --enable-api-write
```

Restore candidate, commit restore i push restore pozostają trzema oddzielnymi
akcjami. Konflikt jednej zależnej części pomija cały jej komponent, ale nie
blokuje innych bezpiecznych komponentów.

Wyszukiwanie po IP obejmuje wszystkie faktycznie zastosowane sesje cleanup dla
tego hosta i administratora. Toolbox kwalifikuje powtarzające się identyfikatory
mutacji nazwą sesji, domyka zależności z zapisanych inventory i odwraca historię
chronologicznie. Dzięki temu przypadek „najpierw usunięty member, później cała
grupa lub polityka” odtwarza najpierw encję, a potem jej wcześniejsze członki.
Kontekst każdej zastosowanej sesji pochodzi z jej integralnego `pre_candidate`,
nie z późniejszego running. Pełna lista sesji źródłowych trafia do manifestu i
raportu restore.

## Zasady bezpieczeństwa wykonania

- analiza zależności powstaje z running; diff z candidate i natywny
  `change-summary` są informacją;
- tuż przed mutacją Toolbox ponownie pobiera running i candidate oraz sprawdza
  fingerprint każdego dotkniętego XPath;
- dla cleanupu planner jest ponownie uruchamiany na aktualnym candidate;
  zmieniony zestaw zależności lub zakres DG konfliktuje tylko powiązany
  komponent zamiast wykonywać nieaktualny plan z running;
- dla przywracanej polityki sprawdzany jest też fingerprint pełnej kolejności
  nazw w konkretnym rulebase; zmiana treści obcej reguły nie blokuje, ale jej
  dodanie, usunięcie lub przesunięcie powoduje konflikt komponentu;
- zmiana poza dotkniętymi ścieżkami nie blokuje batcha;
- ICMP reply pomija IP, timeout dopuszcza analizę, a błąd procesu ICMP pomija
  tylko to IP;
- last-hit z okresu review jest ostrzeżeniem, nie blokadą;
- mutujące POST nie są ponawiane; brak jednoznacznej odpowiedzi daje
  `OUTCOME_UNKNOWN` i wymaga reconciliation;
- znany błąd joba commit pozostawia sesję w stanie zastosowanego candidate, a
  znany błąd push w `COMMITTED`, dzięki czemu etap można bezpiecznie ponowić;
- apply zapisuje snapshoty, backupy encji, manifest i hash-chain journal;
- candidate apply, commit i push są serializowane jednym międzyprocesowym
  mutexem per Panorama; restore ponownie sprawdza watermark historii pod tym
  mutexem i pod config lockami;
- błąd apply uruchamia granularny inverse patch, nigdy pełny `load config`;
- niepełny rollback otrzymuje `OUTCOME_UNKNOWN`, zachowuje blokady i wymaga
  ręcznego reconciliation;
- partial commit może objąć inne zmiany tego samego administratora i dlatego
  wymaga `--allow-unisolated-commit`;
- push używa rozwiniętego zakresu dotkniętych device groups i nie obejmuje
  template changes.

## Sesje i backupy

Domyślna lokalizacja:

```text
%LOCALAPPDATA%\PanOSToolbox\sessions\session-...
```

Katalog otrzymuje ACL bieżącego użytkownika. Dane są plaintext, mają sumy
SHA256 i nie są automatycznie kasowane. Sesja zawiera między innymi:

- `plan_running.xml`, `plan_candidate.xml`;
- snapshoty `pre_*` i `post_*` dla wykonanych etapów;
- `patchset.json` z forward/inverse operations i zależnościami;
- backupy encji `nazwa_DDMMYY_HH_MM_mutation-id.xml`;
- `manifest.json`, append-only journal, job IDs, ryzyka i konflikty;
- `commands.txt`, `raport_krotki.txt`, `raport_szczegolowy.txt` oraz — po
  zapisie — `raport_wykonania_candidate.txt`;
- dla konfliktowego restore: ręczny pakiet `manual_conflicts.json` i
  `manual_conflicts.xml`.

Po przerwaniu procesu (także `Ctrl+C`) w czasie candidate apply, commit lub push
Toolbox przechodzi w `OUTCOME_UNKNOWN`, zachowuje config locki i ukryty marker
`.panorama-job-*.lock` w katalogu sesji. Przerwanie jeszcze przed zmianą stanu
również zachowuje marker fail-closed. Nie usuwaj go przed ręcznym sprawdzeniem
jobów i running/candidate na Panoramie; marker chroni przed przypadkowym replay.

## Budowanie frontendu (tylko maszyna deweloperska)

```powershell
Set-Location .\frontend
npm ci
npm test
npm run build
Copy-Item -Recurse -Force .\dist\* ..\backend\panos_toolbox\static\
```

Do wdrożenia użyj `build_release.ps1`; skrypt przypina i pakuje zależności
Pythona, uruchamia testy oraz doctor rozpakowanego stagingu. Wynikowa paczka
nie wymaga Node.js ani instalowania modułów na maszynie docelowej.

## Walidacja laboratoryjna

Testy na atrapach nie zastępują próby na Panorama 10.2.16-h4. Przed pierwszym
produkcyjnym zapisem wykonaj procedurę z `LAB_VALIDATION.md`, szczególnie
sprawdzenie config lock, partial commit, specific-DG commit-all, UUID reguł i
pozycji restore. Do czasu zaliczenia tej próby pozostaw profil w `read-only`.
