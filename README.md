# Sieci - Network Automation Scripts

Repozytorium zawiera zbiór skryptów do automatyzacji zadań sieciowych, głównie dla środowisk **Palo Alto Networks Panorama** oraz **Illumio**.

## Spis treści

- [Palo Alto Panorama](#palo-alto-panorama)
  - [Weryfikacja hostów i grup](#weryfikacja-hostów-i-grup)
  - [Wyszukiwanie reguł](#wyszukiwanie-reguł)
  - [Analiza użycia reguł (Hit Count)](#analiza-użycia-reguł-hit-count)
  - [Czyszczenie obiektów](#czyszczenie-obiektów)
  - [Generowanie komend wyłączających](#generowanie-komend-wyłączających)
- [Illumio](#illumio)
  - [Illumio Probe](#illumio-probe)
- [Active Directory](#active-directory)
  - [Generator filtrów LDAP](#generator-filtrów-ldap)

---

## Palo Alto Panorama

Skrypty w Pythonie wspomagające zarządzanie politykami i obiektami w Panoramie.

### Weryfikacja hostów i grup
**Pliki:** `Panorama_group_checker_v2`, `panorama_group_checker_update`

Skrypt służy do weryfikacji, czy hosty zdefiniowane w pliku wejściowym są poprawnie skonfigurowane w Panoramie.
- Sprawdza istnienie obiektów adresowych (`H-IP-32`).
- Weryfikuje, czy IP mieści się w zdefiniowanych zakresach (`R-IP-range`).
- Sprawdza przynależność do odpowiednich grup adresowych.
- Raportuje nadmiarowe adresy w grupach.

**Użycie:**
```bash
python3 Panorama_group_checker_v2
```

### Wyszukiwanie reguł
**Plik:** `Panorama_Rule_Finder`

Narzędzie do wyszukiwania reguł bezpieczeństwa zawierających określony adres IP (jako źródło lub cel). Łączy się przez SSH i parsuje konfigurację.

**Użycie:**
```bash
python3 Panorama_Rule_Finder
```

### Analiza użycia reguł (Hit Count)
**Plik:** `Panorama_rules_checker.py`

Skrypt sprawdza licznik trafień (hit count) dla listy reguł podanej w pliku.
- Generuje raporty: `rules_0hit` (nieużywane) oraz `rules_hit` (używane).
- Pomaga w identyfikacji martwych reguł do usunięcia.

**Użycie:**
```bash
python3 Panorama_rules_checker.py
```

### Czyszczenie obiektów
**Pliki:** `Panorama_object_cleanup.py`, `panorama_object_cleaner`

Pomocnik do usuwania obiektów adresowych.
- Przyjmuje listę IP.
- Prosi użytkownika o wykonanie komend `show | match` w CLI Panoramy.
- Na podstawie outputu generuje gotowe komendy `delete` do usunięcia obiektu z polityk, grup i samej definicji obiektu.

**Użycie:**
```bash
python3 Panorama_object_cleanup.py --ip-file ip.txt
```

### Generowanie komend wyłączających
**Plik:** `generate_disable_commands.py`

Prosty generator poleceń CLI do masowego wyłączania reguł (`disabled yes`).
- Przyjmuje listę nazw reguł.
- Generuje plik `rules_disable_cli_pa.txt` z komendami podzielonymi na bloki.

**Użycie:**
```bash
python3 generate_disable_commands.py
```

---

## Illumio

### Illumio Probe
**Plik:** `Ilumio_API` (wewnątrz skrypt bash `illumio_probe.sh`)

Skrypt Bash do szybkiej diagnostyki API Illumio PCE.
- Sprawdza dostępność i wersję PCE.
- Pobiera statystyki labeli, workloadów i namespace'ów (Kubernetes/OpenShift).
- Wymaga `jq` oraz `curl`.

**Użycie:**
```bash
# Ustaw zmienne środowiskowe z kluczami API
KEY="api_key_id" TOKEN="api_key_secret" ./illumio_probe.sh
```

---

## Active Directory

### Generator filtrów LDAP
**Plik:** `pa_ad_group_generator.ps1`

Skrypt PowerShell generujący filtry LDAP (np. do mapowania grup w Palo Alto User-ID).
- Pobiera nazwy grup z pliku `ad_groups.txt`.
- Sprawdza, czy grupy mają członków.
- Generuje filtry w formacie `(|(memberof=CN=...)(memberof=CN=...))` w blokach po 6 grup.

**Użycie:**
```powershell
.\pa_ad_group_generator.ps1
```

---

## Wymagania

Dla skryptów Python zalecane jest utworzenie wirtualnego środowiska i instalacja zależności:
```bash
pip install requests netmiko paramiko
```
(Dokładne wymagania mogą się różnić w zależności od skryptu).
