# PanOS Toolbox

Lokalne GUI i CLI do analizy, generowania oraz kontrolowanego wykonywania
cleanup/restore na Panorama. Serwer nasłuchuje wyłącznie na
`127.0.0.1`; frontend jest statyczny, więc Node.js nie jest wymagany na
maszynie docelowej.

Toolbox domyślnie jest **READ ONLY/generator-only**. W GUI istnieje tylko jedna
bramka: niebieski przełącznik **READ ONLY**, który po ostrzeżeniu zmienia się w
zielony **WRITE**. Nie ma drugiego wyboru profilu ani „poziomu API”. Zapis
wymaga równocześnie:

1. odpowiedniego `api_max_stage` i `--enable-api-write` w CLI; albo
2. nietrwałego przełącznika **WRITE** w lokalnym GUI.

Candidate, commit i push są osobnymi etapami. Żaden etap nie uruchamia
następnego automatycznie. Narzędzie nigdy automatycznie nie ładuje pełnego
backupu konfiguracji.

## Najważniejsze w v0.8.2

- `start_toolbox.ps1` działa w wymuszonym przez AppLocker/WDAC trybie Windows
  PowerShell `ConstrainedLanguage`; release gate odtwarza ten tryb przed
  opublikowaniem paczki;
- starter nie używa metod .NET blokowanych przez politykę organizacji, nie
  zmienia `ExecutionPolicy` i zachowuje obsługę `-Doctor` oraz `-Port`;
- `start_toolbox.cmd` pozostaje podstawowym starterem bez zależności od języka
  skryptowego PowerShell.

## Najważniejsze w v0.8.1

- **Hand Mode** generuje prawdziwe, gotowe do wklejenia komendy PAN-OS CLI dla
  cleanupu, tworzenia obiektów/polityk, Restore oraz Custom LDAP Group;
- aktywny plan, rollback, elementy wykluczone i konfliktowy Restore mają
  oddzielne pliki, przyciski kopiowania/pobierania oraz jawne ostrzeżenia;
- plik komend nigdy nie zawiera JSON, operacji XML API, `configure`, `commit`
  ani `push`; jedna nieobsługiwana operacja blokuje cały plik zamiast
  publikować niepełną listę;
- Historia potrafi offline dopisać Hand Mode do starej sesji z zachowanego
  `patchset.json`, bez logowania, ponownego pobierania configu i nadpisywania
  starego `commands.txt`;
- generator Custom LDAP Group tworzy również komendy template/vsys oraz ich
  rollback; dla kilku bloków filtra używa osobnych nazw `AD__NAZWA__01`,
  `AD__NAZWA__02`, aby nie nadpisywać pojedynczego pola LDAP Filter.
- lokalny backend generuje przy każdym starcie osobny token aplikacji; wszystkie
  endpointy `/api/` wymagają go dodatkowo obok tokenu połączenia z Panoramą;
- odpowiedzi XML są parsowane bez DTD/encji z limitem 512 MiB, poświadczenia
  legacy nie trafiają już do URL ani plików debug, a narzędzia systemowe są
  rozwiązywane wyłącznie z zaufanych katalogów Windows;
- paczka portable zawiera audytowane startery `start_toolbox.cmd` oraz zgodny z
  Windows PowerShell 5.1 `start_toolbox.ps1`, hash-lock zależności i manifest
  integralności.

## Najważniejsze w v0.7.3

- drugi i kolejne batche używają pełnych snapshotów z pamięci wyłącznie po
  potwierdzeniu identycznego, natywnego `change-summary`; zmiana stanu wymusza
  spójne odświeżenie running/candidate;
- zwykły Candidate wykorzystuje zapisane snapshoty planu, równolegle sprawdza
  tylko dotknięte XPath i wykonuje jeden pełny odczyt candidate dopiero po
  zapisie; test regresyjny potwierdza spadek z pięciu pełnych odczytów do jednego;
- Commit i Push w normalnej ścieżce nie pobierają pełnego configu: sprawdzają
  dotknięte XPath odpowiednio w candidate i running, a pełny odczyt pozostaje
  fail-closed fallbackiem dla nieobsługiwanej odpowiedzi API;
- Last Hit oraz sprawdzanie encji dla generatora nowych polityk działają w
  ograniczonej puli do ośmiu równoległych odczytów; inventory dużej rulebase
  korzysta z jednorazowych indeksów zamiast skanować całość dla każdego wiersza;
- trwały journal sesji jest append-only JSONL i nie przepisuje dużego manifestu
  po każdej polityce; starsze sesje są migrowane bez usuwania ich plików;
- ekran wykonania pokazuje żywą odpowiedź joba Panoramy, numer poll, czas,
  pozycję w kolejce i ostrzeżenia, więc długi job nie wygląda już jak zawieszone
  50%; końcowe `FIN/OK` domyka pasek do 100% przy kolejnym pollu.

## Najważniejsze w v0.7.2

- każdy `BLOCK` pokazuje bezpośrednio w GUI dokładny kod, rodzaj różnicy,
  właściciela, DG/rulebase, pole oraz XPath, który zatrzymał commit;
- pełny opis przed commit oraz osobny raport live preflight zawierają te same
  szczegóły, także gdy job zakończy się błędem przed wysłaniem do Panoramy;
- operator może jawnie wybrać **Ignoruj tę blokadę**, ale dopiero po ostrzeżeniu
  i akceptacji fingerprintu dokładnego zestawu findings;
- backend ponawia live scope guard i odrzuca override, jeżeli candidate albo
  choć jeden finding zmieni się pomiędzy wyświetleniem a commitem;
- zaakceptowany override jest trwale zapisany w ryzykach, journalu i raporcie
  sesji razem z fingerprintem oraz kodami ustaleń.

## Najważniejsze w v0.7.1

- wykluczenie polityki, obiektu lub całego komponentu przebudowuje plan
  wyłącznie lokalnie — bez ponownego pobierania running/candidate z Panoramy;
- niezmienne backupy encji i pełne snapshoty są bezpiecznie dziedziczone przez
  plan potomny zamiast ponownego parsowania oraz zapisywania dużego configu;
- pełna kontrola integralności wszystkich odziedziczonych plików nadal działa
  fail-closed bezpośrednio przed Candidate;
- GUI pokazuje jednoznaczny status lokalnej przebudowy, a niezależne pozostałe
  cele można od razu zaznaczać do kolejnych wykluczeń.

## Najważniejsze w v0.7.0

- pełna historia i backupy dostępne bez logowania do Panoramy;
- szybkie wyszukiwanie po IP, nazwie encji, DG, rulebase, XPath i session ID;
- dokładna oś czasu per mutacja: plan, Candidate, commit, push i Restore;
- rozróżnienie planu od potwierdzonego wykonania oraz szybkie przygotowanie
  Restore dla atomowego komponentu zależności;
- osobny podgląd/pobieranie każdego backupu bez ponownego haszowania wszystkich
  dużych snapshotów sesji.

## Szybki start na maszynie docelowej

Wymagany jest Python 3.10+ i rozpakowana paczka zawierająca gotowy frontend.
Paczka release zawiera zależności webowe w `backend/vendor`: nie wymaga
Node.js, `pip install`, praw administratora ani lokalnego serwera IIS/Apache.

Pobierz asset ZIP z [najnowszego GitHub Release](https://github.com/Szqub/Sieci/releases/latest).
Checkout utworzony przez `git clone` jest kodem źródłowym i celowo nie zawiera
`backend/vendor`; na maszynie docelowej uruchamiaj wyłącznie paczkę portable.

Jeżeli firmowe **Pobrane** lub **Dokumenty** są przekierowane na SMB, wybierz w
oknie zapisu zatwierdzony katalog lokalny, na przykład
`%LOCALAPPDATA%\PanOS Toolbox\downloads`, i również tam rozpakuj ZIP. Zapis
bezpośrednio do przekierowanego katalogu może wygenerować `SMB MOVE` już po
stronie przeglądarki (`.crdownload`/plik tymczasowy → finalny ZIP), zanim kod
Toolboxa zostanie uruchomiony.

Najprościej: wybierz w Eksploratorze **Wyodrębnij wszystkie**, wejdź do katalogu
`PanOS-Toolbox` i uruchom dwuklikiem `start_toolbox.cmd`. Jeżeli polityka stacji
preferuje Windows PowerShell 5.1, uruchom `start_toolbox.ps1` przez systemowy
`powershell.exe`; skrypt nie zmienia Execution Policy. Oba startery sprawdzają
kompletność paczki i uruchamiają Pythona z `-I -B -S`, więc globalny Flask nie jest
używany. Historia i backupy są zapisywane trwale w lokalnym profilu użytkownika:
`%LOCALAPPDATA%\PanOS Toolbox\sessions`; pozostają po zamknięciu aplikacji i nie
zależą od miejsca rozpakowania ZIP-a. Ten sam lokalny folder zawiera
zaszyfrowane profile połączeń w `profiles.json`.

```powershell
$appRoot = Join-Path $env:LOCALAPPDATA "PanOS Toolbox\app"
Expand-Archive .\PanOS-Toolbox-YYYYMMDD-HHMMSS.zip -DestinationPath $appRoot
Set-Location (Join-Path $appRoot "PanOS-Toolbox")
.\start_toolbox.cmd
```

Dostępne launchery i diagnostyka:

```powershell
.\start_toolbox.cmd
.\start_toolbox.cmd doctor
powershell.exe -NoLogo -NoProfile -File .\start_toolbox.ps1
powershell.exe -NoLogo -NoProfile -File .\start_toolbox.ps1 -Doctor
powershell.exe -NoLogo -NoProfile -File .\start_toolbox.ps1 -Port 9000
```

Backend automatycznie otwiera przeglądarkę z jednorazowym linkiem zawierającym
token lokalnej aplikacji. Jeżeli przeglądarka się nie otworzy, skopiuj dokładny
`bezpieczny link tej sesji` wyświetlony w konsoli; samo wejście na goły adres
`http://127.0.0.1:8765/` nie uwierzytelni wywołań API. Serwera nie uruchamiaj z bindem
`0.0.0.0` ani na interfejsie sieciowym.

### Dystrybucja zgodna z kontrolami bezpieczeństwa

Nie zmieniaj rozszerzenia ZIP-a, nie umieszczaj paczki w archiwum chronionym
hasłem i nie próbuj omijać NDR/EDR. Release jest budowany fail-closed: nie
zawiera własnych plików PE (`.exe`, `.dll`, `.pyd`, `MZ`). Zawiera wyłącznie
dwa jawnie allowlistowane launchery: czytelny `start_toolbox.cmd` oraz
`start_toolbox.ps1` zgodny z Windows PowerShell 5.1, również w trybie
`ConstrainedLanguage`. Oba uruchamiają
zatwierdzonego firmowego Pythona z `-I -B -S`; PS1 nie omija Execution Policy. Flaga `-B` oraz
entrypoint wyłączają zapis `__pycache__`, dzięki czemu katalog rozpakowanej
paczki może pozostać tylko do odczytu również wtedy, gdy leży na SMB.

Wewnątrz paczki znajdują się `RELEASE-MANIFEST.json` oraz `SHA256SUMS.txt` z
rozmiarem i SHA-256 każdego pliku, SHA commita oraz jawnym polem
`sourceTreeDirty`. Obok ZIP-a build tworzy plik
`PanOS-Toolbox-....zip.sha256`. Jeżeli ochrona nadal blokuje transfer, przekaż
zespołowi bezpieczeństwa URL wydania, SHA-256 ZIP-a i manifest do jawnej
allowlisty. Kolejna zmiana formatu lub rozszerzenia nie jest właściwym
obejściem polityki.

Mutowalny magazyn sesji nie może wskazywać UNC, mapowanego dysku SMB ani
przekierowanego folderu Dokumenty. Atomowe zapisy integralnościowe używają
lokalnego rename, który na udziale byłby widoczny dla NDR jako `SMB MOVE`.
Toolbox blokuje taki magazyn i domyślnie używa `LocalAppData`. Przy pierwszym
uruchomieniu kopiuje kompletne wcześniejsze sesje i profile z
`Dokumenty\PanOS Toolbox` do lokalnego magazynu, wyłącznie je odczytując i nie
usuwając źródła.

Host, użytkownik i hasło wpisujesz w GUI. Zaznaczenie **Zapamiętaj profil**
zapisuje host, login, ustawienia SSL i hasło zaszyfrowane przez Windows DPAPI
w profilu bieżącego użytkownika. Ponowne połączenie może użyć profilu bez
ponownego wpisywania hasła; zmiana hasła następuje po wpisaniu nowego hasła i
ponownym zapisaniu profilu. Lokalny GUI używa jednego, nietrwałego grantu WRITE; każde wywołanie API wymaga
dodatkowo losowego tokenu aplikacji wygenerowanego przy starcie. Token trafia do
fragmentu URL, jest usuwany z paska adresu i pozostaje tylko w pamięci backendu
oraz `sessionStorage` tej karty. GUI nadal wymaga zgodności
hosta, aktywnego connection tokenu, poprawnego Origin i jawnego potwierdzenia
przełącznika zapisu. Połączenie wykonuje keygen, odczyt `show system info` i
`change-summary` — nie pobiera wtedy pełnego configu. Wyświetlana wersja PAN-OS
pochodzi bezpośrednio z `sw-version`, a nie z atrybutu pliku konfiguracji.

Nie instaluj Flask ani innych modułów globalnie. Paczka release ma przypięty
Flask i jego zależności w `backend/vendor`; tryb `-I -B -S` w poleceniu Doctor
potwierdza, że Toolbox nie korzysta z przypadkowych pakietów użytkownika.

`ip.txt` i `panorama_host.txt` nie są wymagane przez GUI. Pozostają wyłącznie
opcjonalnymi wejściami kompatybilności dla CLI; połączenie, profil, historia i
backupy działają z lokalnego katalogu użytkownika
`%LOCALAPPDATA%\PanOS Toolbox`.

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

Ekran ma dwa tryby:

- **Punktowo** — 1–20 dokładnych nazw lub IP. Toolbox wysyła wąskie zapytania
  XPath do `shared` i wskazanych DG, nie pobiera całego `/config`, pokazuje
  lokalizację, pola polityki, komentarz, Last Hit i zależności;
- **Lista / batch** — buduje pełny graf zależności na snapshotach running i
  candidate. Pierwszy batch pobiera je z Panoramy, a kolejne plany w tym samym
  połączeniu korzystają z cache przez maksymalnie 30 minut wyłącznie wtedy, gdy
  dokładny natywny `change-summary` nadal jest identyczny.

Analiza batch działa jako asynchroniczny job i pokazuje procentowy postęp dla
ICMP, pobierania/cache running i candidate, grafu zależności, równoległego Last
Hit oraz zapisu artefaktów. Przed realnym WRITE cache nie jest zaufany:
Candidate potwierdza dokładny proof planu i sprawdza live tylko dotknięte XPath;
przy jakiejkolwiek zmianie przechodzi na pełny fail-closed fallback. Po
zastosowaniu operacji pobiera jeden pełny candidate, sprawdza wszystkie
postcondition i automatycznie tworzy pełny diff running → candidate oraz ścisły
scope guard. Commit ponownie potwierdza `change-summary` i dotknięte XPath
candidate, a Push dotknięte XPath running. Pełny config w tych dwóch etapach
jest pobierany tylko jako awaryjny fallback. Jawne **Odśwież diff** celowo
pobiera pełny running i candidate, bo operator żąda wtedy kompletnego nowego
przeglądu całej konfiguracji.
Po analizie przy każdym bezpiecznym celu jest przycisk **Tylko ten**. Można też
zaznaczyć dowolne wiersze albo konkretne zależności i przygotować nowy batch.
Wydzielany jest cały atomowy komponent zależności, dzięki czemu obiekt, grupa
lub polityka mogą być wykonane oddzielnie bez częściowego uszkodzenia grafu.

Każdy wykonywalny wiersz ma również akcję **Wyklucz**, a zaznaczone wiersze
można usunąć z wykonania zbiorczo przez **Wyklucz zaznaczone**. Toolbox tworzy
nową, trwałą sesję-plan i pozostawia plan źródłowy bez zmian. Wykluczenie jest
rozszerzane na cały atomowy komponent zależności; jeżeli wspólna polityka,
grupa lub obiekt łączy kilka celów, wszystkie cele pośrednio dotknięte są jawnie
oznaczone jako wykluczone. Pozostają widoczne w raporcie, ale nie trafiają do
backupu wykonawczego, operacji XPath ani Candidate tej sesji. Przycisk
**Cofnij ostatnie wykluczenie** wraca do bezpiecznie zachowanego planu
nadrzędnego. Po rozwinięciu celu sekcja **Atomowe komponenty wykonawcze**
pokazuje wszystkie rzeczywiste operacje na politykach, grupach i obiektach.
Akcja **Wyklucz cały komponent** pozwala odrzucić konkretną znalezioną encję;
Toolbox automatycznie domyka wykluczenie na zależności, aby nie pozostawić
reguły wskazującej na usunięty obiekt ani wykonać połowy komponentu.

Wiersze są rozwijane. Dla polityki pokazują DG, pre/post-rulebase, typ reguły,
strefy from/to, source, destination, service, application, tagi, komentarz i
rzeczywiste zależności obiektów/grup. Last Hit ma stałe kolory: zielony dla
braku hitów/braku Last Hit lub wieku co najmniej pół roku, żółty od miesiąca,
pomarańczowy od dwóch tygodni i czerwony poniżej dwóch tygodni.

Application Override jest traktowany fail-closed. Bezpośrednio wskazana reguła
oraz każdy obiekt/grupa zależna od takiej reguły są oznaczone
`APP_OVERRIDE_READ_ONLY`, raportowane w GUI i wyłączane z automatycznych mutacji.
Chroni to batch przed zatrzymaniem na regule dziedziczonej albo read-only.

Polityka o nazwie `DEFAULT` jest dodatkową granicą bezpieczeństwa. Jeżeli
wybrany IP, obiekt, grupa albo polityka dotyka `DEFAULT` lub jej zależności,
cały powiązany komponent zostaje automatycznie wykluczony z usuwania i jest
oznaczony `DEFAULT_POLICY_PROTECTED`. W ekranie Cleanup opcja **Zezwól na
naruszenie DEFAULT** jest domyślnie wyłączona. Jej włączenie zapisuje jawne
ostrzeżenie w manifeście i raporcie, a przed Candidate pojawia się osobne
potwierdzenie ryzyka; bez niego polityka `DEFAULT` nie jest modyfikowana.

Wszystkie ostrzeżenia analizy, blokady read-only, puste/brakujące grupy AD i
konflikty Restore są dodatkowo zebrane w jednej sekcji **Uwagi** w sidebarze.
Pomarańczowy badge pokazuje liczbę aktywnych uwag; lista główna nie jest przez
nie zasłaniana. Szczegóły planu i operacji pozostają w rozwijanym panelu na dole.

Kliknięcie **Analizuj zależności** niczego nie zapisuje. Wynikiem są: plan GUI,
komendy CLI, raport krótki, raport szczegółowy i manifest. Candidate, commit i
push pozostają trzema osobnymi, jawnymi etapami.

Lista planu jest domyślnie sortowana od najnowszego Last Hit. Przyciski **<14
dni**, **<1 miesiąc** i **<3 miesiące** pozwalają jednym kliknięciem wykluczyć
świeże cele przed wykonaniem; wykluczenie dotyczy tylko wybranych atomowych
komponentów i nie blokuje niezależnych pozycji.

## Nowe polityki z wklejki ServiceNow

Sekcja **Nowe polityki** przyjmuje bezpośrednio wklejkę zawierającą `Passes
ToDo`, `Info Src` i `Info Dst` w JSON, Python repr albo mieszanym formacie.
`Passes Done` jest ignorowane i trafia do ostrzeżeń. Toolbox nie pobiera
pełnego configu: dla każdego obiektu, grupy, usługi i reguły wykonuje punktowe
odczyty XML API w running oraz candidate, do ośmiu encji równolegle, a następnie
pokazuje plan do ręcznej akceptacji.

Generator przygotowuje osobne mutacje z backupem i rollbackiem w podanym DG,
rulebase oraz strefach. Konwencje nazw to `H-IP-32` dla hosta, `N-SIEC-PREFIX`
dla sieci, `HG__NAZWA` dla grupy, `SVC__PORT-protocol` dla usługi i
`SOURCE__DESTINATION` dla polityki. Istniejące encje są pomijane z
ostrzeżeniem; zapis do Candidate nadal wymaga zielonego WRITE.

W sekcji **Wykonanie kontrolowane** nie ma wyboru „poziomu API”. Zielony WRITE
odblokowuje trzy osobne przyciski zgodnie ze stanem sesji. Candidate wykonuje
po XML API każdą operację XPath osobno; pasek pokazuje backup, locki, live
recheck, bieżącą encję, liczbę operacji, walidację i przygotowanie przeglądu
przed commit. Toolbox nie wgrywa całego pliku konfiguracji.

Po Candidate duże, kompaktowe okno **Pełny przegląd przed Commit** pokazuje
dokładne zmiany, operacje, XPath, device group/rulebase, przyczynę zmiany oraz
wszystkie znaleziska scope guard. Można je szybko filtrować po nazwie obiektu,
polityki, DG albo XPath. Pełny diff XML i szczegółowy raport są dostępne przez
osobne akcje **Wyświetl** i **Pobierz**. Te same dwie akcje są dostępne dla
każdego tekstowego artefaktu sesji, w tym CLI, manifestu i backupów encji.

Scope guard odtwarza oczekiwany candidate lokalnie z dokładnego PatchSetu i
porównuje go z live candidate. Commit jest blokowany, jeżeli znajdzie choć jedną
zmianę poza planem albo pozostałą referencję do usuwanego adresu/grupy — na
przykład w innej polityce, grupie nadrzędnej lub nieobsługiwanym polu. Operator
może odświeżyć diff bez ponownego zapisu Candidate.

Przy `BLOCK` GUI pokazuje każde ustalenie przed przyciskiem commit: kod, rodzaj
różnicy XML, obiekt będący właścicielem, DG/rulebase, pole i dokładny XPath.
Przycisk **Ignoruj tę blokadę** wymaga WRITE, osobnego ostrzeżenia i zaznaczenia
potwierdzenia. Nie wyłącza scope guard globalnie: przekazuje fingerprint obecnego
zestawu findings, a backend przed dispatch ponownie liczy live guard i pozwala
kontynuować wyłącznie wtedy, gdy fingerprint jest identyczny. Override oraz jego
raport są zapisywane w trwałej historii sesji.

Commit ma osobne ostrzeżenie, a push mocniejsze ostrzeżenie z listą device
groups. Commit i push działają jako joby w tle. Przed realnym wysłaniem commit
GUI jawnie pokazuje **job nie został jeszcze wysłany do Panoramy** i postęp
preflightu. Dopiero po PASS pojawia się Panorama job ID, status i procent
raportowany przez urządzenie. Gdy PAN-OS nie zwraca procentu, pasek jest
animowany, a log pokazuje kolejne odpytywania zamiast zatrzymywać się na
pozornych 50%. Wpis techniczny `*-dispatched` znika z listy aktywnych po
pojawieniu się terminalnego `FIN`. CLI nadal respektuje `api_max_stage` profilu.

Optymalizacja v0.6.0 ogranicza normalny preflight commit do jednego pełnego
odczytu live candidate. Nie wykonuje blokującego pobrania running po zakończeniu
joba — wynik Panorama `FIN/OK` od razu kończy etap, a running zostaje ponownie
sprawdzony przez Push albo późniejszy Audit. Sam partial commit i specific-DG
commit-all pozostają pojedynczymi jobami Panoramy; rozbijanie ich na commit per
obiekt byłoby wolniejsze i zwiększałoby ryzyko częściowego stanu.

## Generator Custom LDAP Group z Active Directory

Sekcja **Grupy AD** przenosi do GUI workflow ze skryptu
`pa_ad_group_generator.ps1`. Nie wymaga połączenia z Panorama. Przyjmuje dużą
listę nazw grup AD, nazwę wynikową, Device Template, nazwę Group Mapping i
VSYS. Device Template jest wymagany do wygenerowania bezpiecznych komend Hand
Mode; bez niego nadal można przejrzeć wynik walidacji/filtry, ale status CLI
będzie `BLOCK`. Domyślne miejsce docelowe to `LDAP_GM1` oraz `vsys1`.

Toolbox wykonuje lokalnie dokładne, read-only zapytania `dsquery group` i
`dsget group -members` dla każdej unikalnej nazwy `sAMAccountName`. Są to
narzędzia Microsoft dostarczane z RSAT; Toolbox nie uruchamia PowerShella, nie
zmienia Execution Policy, nie używa shella i nie przekazuje poświadczeń w
parametrach procesu. Znaki wieloznaczne `*` i `?` są odrzucane, aby lista wejścia
nie mogła zmienić się w szeroką enumerację katalogu.

Do wyniku trafiają wyłącznie grupy, które istnieją i mają co najmniej jednego
bezpośredniego członka. Brakujące, puste oraz grupy z błędem odczytu są pokazane
osobno i pomijane. Distinguished Name jest zamieniany na filtr
`(memberof=...)`; filtry są grupowane operatorem OR po maksymalnie sześć wpisów,
tak jak w dotychczasowym skrypcie. Znaki specjalne wartości filtra są escapowane
zgodnie z RFC 4515.

Nazwa wynikowa zawsze otrzymuje kanoniczny prefiks `AD__`. Wpisanie `VPN_USERS`
da `AD__VPN_USERS`; istniejący prefiks nie zostanie zdublowany. GUI pokazuje
gotowe bloki oraz prawdziwe komendy `set template ... config vsys ...
group-mapping ... custom-group ... ldap-filter ...`. Pozwala kopiować/pobierać
cały zestaw i osobny rollback. Commit ani push nie są dodawane.

Walidacja wymaga `dsquery.exe` i `dsget.exe` z RSAT Active Directory Domain
Services na stacji uruchamiającej Toolbox. Paczka nie instaluje RSAT ani żadnego
modułu globalnie. Generator korzysta z bieżącej tożsamości Windows i jest
read-only: nie tworzy ani nie modyfikuje grup w AD i nie zapisuje konfiguracji
Panoramy. Składnia narzędzi jest opisana w dokumentacji Microsoft:
[dsquery group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754525(v=ws.11))
oraz
[dsget group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731202(v=ws.11)).
Docelowe miejsce w GUI Panorama to:

```text
Device Templates > [template] > User Identification > Group Mapping Settings
> LDAP_GM1 > Custom Group (VSYS: vsys1)
```

Semantykę pojedynczego pola LDAP Filter oraz limity Group Mapping należy
sprawdzić według oficjalnego opisu
[Group Mapping Settings](https://docs.paloaltonetworks.com/ngfw/help/11-1/user-identification/device-user-identification-group-mapping-settings).
Automatyczny zapis tej sekcji przez XML API pozostaje wyłączony; obecna
funkcja generuje wyłącznie ręczny Hand Mode i rollback.

Test read-only API (keygen, running, candidate) jest opcjonalny:

```powershell
python .\panos-toolbox.py doctor --host-file .\panorama_host.txt --api-check
```

Hasło ani uzyskany przez keygen API key nie są zapisywane w raportach, logach
ani storage przeglądarki; klucz API bieżącej sesji jest wyłącznie w pamięci
procesu. Tylko jawnie zapisany profil ma zaszyfrowane pole hasła DPAPI. Bez
zmiennej środowiskowej CLI wyświetli ukryty prompt. W PowerShell 7
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
- `verify_ssl=yes` weryfikuje certyfikat HTTPS; w GUI weryfikacja certyfikatu
  jest domyślnie wyłączona i można ją włączyć na ekranie połączenia;
- `api_max_stage`: `read-only`, `candidate`, `commit` albo `push`;
- brak `api_max_stage` oznacza `read-only`.

`api_max_stage` pozostaje twardą granicą CLI. W lokalnym GUI zastępuje ją jedna
świadoma bramka **READ ONLY / WRITE**. Krótki lease wykonania jest tworzony dla
konkretnego żądania dopiero po potwierdzeniu WRITE, jest przechowywany wyłącznie
w pamięci i pozostaje związany z hostem bieżącego połączenia. Po odświeżeniu,
rozłączeniu albo restarcie aplikacji GUI wraca do READ ONLY.

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

Chronioną politykę `DEFAULT` można jawnie objąć planem wyłącznie po świadomej
akceptacji ryzyka:

```powershell
python .\panos-toolbox.py cleanup plan --policy DEFAULT --allow-default-policy-override
```

Etapy zapisu wymagają profilu z odpowiednim limitem i jawnej flagi:

```powershell
python .\panos-toolbox.py cleanup apply --session SESSION_ID --enable-api-write
python .\panos-toolbox.py session commit --session SESSION_ID --enable-api-write --allow-unisolated-commit
python .\panos-toolbox.py session push --session SESSION_ID --enable-api-write --device-group DG1
```

Po `cleanup plan` skopiuj `session_id` z wyniku. Przed `apply`, `commit` i
`push` przejrzyj `commands.txt`, `handmode_instructions.txt`,
`raport_szczegolowy.txt`, ostrzeżenia Last Hit
oraz wyliczony zakres device groups. Nazwy przekazane przez `--object`,
`--group` i `--policy` są dokładne i każdą opcję można powtarzać.

Full commit jest osobnym, najwyższym ryzykiem:

```powershell
python .\panos-toolbox.py session commit --session SESSION_ID --enable-api-write --full --allow-full-commit
```

Emergency Restore można przygotować po IP, identyfikatorze celu albo jawnej
sesji. GUI pozwala wybrać ostatnią stabilną sesję, kilka celów lub całą sesję:

```powershell
python .\panos-toolbox.py restore plan --ip 10.0.0.10
python .\panos-toolbox.py restore plan --source-session SESSION_ID
python .\panos-toolbox.py restore apply --session RESTORE_SESSION_ID --enable-api-write
```

Restore candidate, commit restore i push restore pozostają trzema oddzielnymi
akcjami, a Restore Candidate ma taki sam postęp per XPath jak cleanup.
Konflikt jednej zależnej części pomija cały jej komponent, ale nie blokuje
innych bezpiecznych komponentów.

Wyszukiwanie po IP obejmuje wszystkie faktycznie zastosowane sesje cleanup dla
tego hosta i administratora. Toolbox kwalifikuje powtarzające się identyfikatory
mutacji nazwą sesji, domyka zależności z zapisanych inventory i odwraca historię
chronologicznie. Dzięki temu przypadek „najpierw usunięty member, później cała
grupa lub polityka” odtwarza najpierw encję, a potem jej wcześniejsze członki.
Kontekst każdej zastosowanej sesji pochodzi z jej integralnego `pre_candidate`,
nie z późniejszego running. Pełna lista sesji źródłowych trafia do manifestu i
raportu restore.

## Hand Mode — ręczne wykonanie w PAN-OS CLI

Hand Mode jest projekcją tego samego, zapisanego PatchSetu, który wykonuje
ścieżka XML API. Nie jest drugim plannerem. Zachowuje kolejność mutacji,
atomowe komponenty zależności, pozycje polityk (`move`) i operacje odwrotne.
Obsługuje usuwanie oraz tworzenie adresów, grup, członków grup, usług,
polityk i bezpiecznego Restore.

Najważniejsze pliki sesji:

- `commands.txt` — tylko aktywny plan; w starej sesji z zajętą nazwą nowy
  renderer zapisze `handmode_commands.txt` i zachowa oryginał bez zmian;
- `handmode_rollback.txt` — operacje odwrotne w bezpiecznej kolejności;
- `handmode_instructions.txt` — status `READY` albo `BLOCK`, liczba komend i
  ostrzeżenia o odwzorowaniu XML;
- `handmode_excluded_commands.txt` — osobny, czerwony zestaw elementów
  wykluczonych przez operatora, Last Hit, ochronę `DEFAULT` albo zależność;
- `handmode_conflict_restore_commands.txt` — osobny, czerwony zestaw Restore
  odrzucony przez merge trójstronny.

Pliki z elementami wykluczonymi lub konfliktowymi **nie należą do aktywnego
planu**. GUI wymaga dodatkowego potwierdzenia przed ich skopiowaniem. Nie łącz
ich z `commands.txt` bez kontroli aktualnego configu i raportu sesji.

Ręczne wykonanie:

```text
> set cli scripting-mode on
> configure
# [wklej całą zawartość commands.txt]
# show | compare
```

Po `show | compare` operator sam podejmuje osobną decyzję o commit oraz push
zgodnie z procedurą firmy. Pliki Hand Mode celowo nie zawierają tych komend.
Jeżeli CLI odrzuci choć jedną linię, przerwij, zachowaj komunikat i nie
commituj częściowego wyniku przed porównaniem candidate. Rollback również
należy wkleić w `configure` i sprawdzić przez `show | compare`.

Na ekranie **Backup i restore** starsza sesja ma przycisk **Wygeneruj Hand Mode
offline**. Operacja czyta wyłącznie integralny lokalny `patchset.json`, dopisuje
nowe artefakty append-only i nie kontaktuje się z Panoramą. Po ręcznym
wykonaniu użyj **Zweryfikuj wykonanie CLI/API**, aby live postcondition
rozstrzygnął, czy sesja może być źródłem Restore.

Składnia renderera jest oparta na oficjalnej hierarchii
[PAN-OS CLI](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-configure-cli-command-hierarchy).
Przed użyciem produkcyjnym trzeba zaliczyć checklistę `LAB_VALIDATION.md` na
konkretnej wersji Panorama 10.2 używanej w firmie.

## Zasady bezpieczeństwa wykonania

- analiza zależności powstaje z running; po Candidate pełny diff running →
  candidate i natywny `change-summary` stają się obowiązkowym przeglądem przed
  commit;
- tuż przed Candidate Toolbox pobiera live running/candidate; commit po locku
  pobiera jeden live candidate i lekki `change-summary` (pełny running tylko
  jako fallback), a push jeden live running, zawsze sprawdzając fingerprint
  każdego dotkniętego XPath;
- commit porównuje live candidate z zatwierdzonym przeglądem, odtwarza
  oczekiwany stan z PatchSetu i blokuje każdą zmianę poza planem lub referencję
  do usuwanej encji pozostawioną poza zakresem;
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
- nazwa snapshotu zapisywanego na serwerze ma najwyżej 32 znaki; backend
  sprawdza limit przed wywołaniem PAN-OS;
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

Jeżeli operator wykonał wygenerowane komendy poza Toolboxem, samo wygenerowanie
pliku nie jest traktowane jako wykonanie. W Historii użyj **Zweryfikuj wykonanie
CLI/API**. Toolbox pobierze live running i candidate, sprawdzi postcondition
każdej operacji oraz pozycję polityk i dopiero przy pełnej zgodności oznaczy
sesję jako `CANDIDATE_APPLIED` albo `COMMITTED`, udostępniając ją dla Restore.

## Sesje i backupy

Paczka portable uruchamiana launcherem zapisuje sesje w:

```text
%LOCALAPPDATA%\PanOS Toolbox\sessions\session-...
```

Jawne uruchomienie CLI bez `--session-dir` używa tego samego katalogu. Dane
sesji są chronione ACL-em użytkownika, mają sumy SHA256 i nie są automatycznie
kasowane. Toolbox odrzuca `--session-dir` oraz `PANOS_TOOLBOX_DATA_DIR`
wskazujące UNC albo mapowany dysk sieciowy; bezpośredni zapis aktywnego
journalu na SMB nie jest obsługiwany. Ekran **Backup i restore** działa także
bez połączenia, hosta, loginu i hasła do Panoramy. Buduje lokalny indeks ze
wszystkich zachowanych manifestów, PatchSetów i hash-chain journali.
Wyszukiwanie jest natychmiastowe po pierwszym odczycie i obejmuje między innymi:

- IP i prefiks, nazwę polityki, obiektu, grupy oraz usługę;
- device group, shared, pre/post-rulebase i typ polityki;
- XPath, session ID, operatora, host zapisany w sesji oraz cel wejściowy;
- wartości i referencje zachowane wewnątrz backupów XML.

Dla każdej mutacji GUI rozróżnia **tylko plan** (brak dowodu wykonania) od
rzeczywistego zapisu i pokazuje dokładny czas Candidate, commit, push oraz
Restore. Brak wyniku oznacza brak śladu w lokalnie zachowanych sesjach, a nie
potwierdzenie, że encja nigdy nie istniała w Panoramie. Uszkodzona sesja jest
jawnie raportowana i nie ukrywa pozostałej historii.

Każdy tekstowy backup i artefakt ma osobne akcje **Wyświetl** oraz **Pobierz**.
Podgląd sprawdza sumę tylko wskazanego pliku, dlatego nie czyta ponownie
wszystkich dużych snapshotów. Pełny ZIP nadal przechodzi weryfikację całej
sesji. Przy zastosowanej mutacji przycisk **Przygotuj Restore** przenosi jej
atomowy komponent i zależności do Emergency Restore. Sam odczyt działa offline;
przed utworzeniem planu Restore Toolbox wymaga połączenia, porównuje live
running/candidate i niczego nie zapisuje bez osobnego WRITE oraz potwierdzeń.

GUI pozwala też pobrać integralnie zweryfikowany ZIP całej sesji albo otworzyć
Restore konkretnego celu. Sesja
przy pierwszym uruchomieniu próbuje skopiować stare sesje z
`Dokumenty\PanOS Toolbox\sessions`, `backupy\sessions` obok poprzedniej paczki
oraz z wcześniejszego `LOCALAPPDATA`; źródło pozostaje niezmienione. Pliki
tymczasowe po przerwanych zapisach nie są importowane.
Sesja zawiera między innymi:

- `plan_running.xml`, `plan_candidate.xml`;
- snapshoty `pre_*` i `post_*` dla wykonanych etapów;
- `patchset.json` z forward/inverse operations i zależnościami;
- backupy encji `nazwa_DDMMYY_HH_MM_mutation-id.xml`;
- `manifest.json`, append-only journal, job IDs, ryzyka i konflikty;
- `commands.txt`/`handmode_commands.txt`, `handmode_rollback.txt`,
  `handmode_instructions.txt`, `raport_krotki.txt`, `raport_szczegolowy.txt` oraz — po
  zapisie — `raport_wykonania_candidate.txt`;
- po Candidate: `pre_commit_review_*.json`, czytelny
  `pre_commit_review_*.txt`, pełny `candidate_diff_*.txt` i
  `scope_guard_*.txt`; każdy plik można wyświetlić lub pobrać osobno z GUI;
- dla konfliktowego restore: ręczny pakiet `manual_conflicts.json`,
  `manual_conflicts.xml`, osobne komendy
  `handmode_conflict_restore_commands.txt` i ich rollback.

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
nie wymaga Node.js ani instalowania modułów na maszynie docelowej. Build usuwa
nieużywane launchery konsolowe tworzone przez `pip`, odrzuca wszystkie natywne
PE oraz nieallowlistowane skrypty, a następnie generuje manifest oraz sumy SHA-256.

## Walidacja laboratoryjna

Testy na atrapach nie zastępują próby na Panorama 10.2.16-h4. Przed pierwszym
produkcyjnym zapisem wykonaj procedurę z `LAB_VALIDATION.md`, szczególnie
sprawdzenie config lock, partial commit, specific-DG commit-all, UUID reguł i
pozycji restore. Do czasu zaliczenia tej próby pozostaw profil w `read-only`.
