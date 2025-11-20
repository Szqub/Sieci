# Dokumentacja Skryptów Automatyzacji Sieciowej

To repozytorium zawiera zestaw zaawansowanych skryptów do zarządzania, weryfikacji i czyszczenia konfiguracji w środowiskach sieciowych, ze szczególnym naciskiem na **Palo Alto Networks Panorama**.

Poniżej znajduje się szczegółowa dokumentacja każdego narzędzia, opisująca jego logikę działania, wymagania oraz sposób użycia.

---

## Spis Treści

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
