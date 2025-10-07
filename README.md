# Skrypty do zarządzania Palo Alto Networks Panorama

Kolekcja skryptów do zarządzania i weryfikacji konfiguracji w systemie Palo Alto Networks Panorama.

## Wymagania

- Python 3.6+
- Moduły:
  - requests
  - xml.etree.ElementTree
  - getpass
  - ipaddress

## Instalacja

1. Sklonuj repozytorium:
```bash
git clone https://github.com/twoj-username/panorama-scripts.git
cd panorama-scripts
```

2. Zainstaluj wymagane moduły:
```bash
pip install -r requirements.txt
```

## Dostępne skrypty

### 1. Panorama Rules Checker
Skrypt do sprawdzania hit count dla reguł w Palo Alto Networks Panorama.

#### Opis
Skrypt służy do weryfikacji hit count dla reguł zdefiniowanych w pliku wejściowym w systemie Palo Alto Networks Panorama. Dla każdej reguły sprawdzany jest hit count i w zależności od wyniku, reguła jest zapisywana do odpowiedniego pliku wyjściowego.

#### Użycie
1. Zmień wartość `panorama_ip` w skrypcie na właściwy adres IP Panoramy
2. Przygotuj plik wejściowy z nazwami reguł (jedna nazwa na linię)
3. Uruchom skrypt:
```bash
python Panorama_rules_checker.py
```
4. Postępuj zgodnie z instrukcjami na ekranie:
   - Podaj dane logowania
   - Wybierz device group
   - Wybierz rulebase
   - Podaj ścieżkę do pliku z nazwami reguł

#### Format danych
- **Wejściowy**: plik tekstowy z nazwami reguł (jedna na linię)
- **Wyjściowy**: dwa pliki:
  - `rules_0hit` - reguły z zerowym hit count
  - `rules_hit` - reguły z hit count > 0

### 2. Panorama Group Checker
Skrypt do weryfikacji konfiguracji hostów w grupach adresowych.

#### Opis
Skrypt służy do weryfikacji, czy hosty zdefiniowane w pliku wejściowym są poprawnie skonfigurowane w systemie Palo Alto Networks Panorama. Dla każdego hosta weryfikowane są:
1. Czy istnieje odpowiedni obiekt adresowy typu H-IP-32 w Panoramie
2. Jeśli nie, czy adres IP znajduje się w zakresie jakiegoś obiektu typu R-IP-range
3. Czy obiekt adresowy jest przypisany do odpowiedniej grupy adresowej

#### Użycie
1. Zmień wartość `panorama_ip` w skrypcie na właściwy adres IP Panoramy
2. Przygotuj plik wejściowy w formacie:
```
nazwahosta-grX 10.10.10.10
```
gdzie:
- nazwahosta - nazwa hosta
- grX - nazwa grupy, do której powinien być przypisany host (np. gr1, gr2)
- 10.10.10.10 - adres IP hosta
3. Uruchom skrypt:
```bash
python Panorama_group_checker_v2
```

#### Format danych wyjściowych
```
nazwahosta-grX 10.10.10.10 to obiekt H-10.10.10.10-32 na PA i znajduje się w grupie grX
```
lub
```
nazwahosta-grX 10.10.10.40 to obiekt R-10.10.10.30-50 na PA i znajduje się w grupie grX
```

### 3. Panorama Rule Finder
Skrypt do wyszukiwania reguł w konfiguracji Panoramy.

#### Opis
Skrypt służy do wyszukiwania reguł w konfiguracji Palo Alto Networks Panorama na podstawie różnych kryteriów (nazwa, źródło, cel, aplikacja, itp.).

#### Użycie
1. Zmień wartość `panorama_ip` w skrypcie na właściwy adres IP Panoramy
2. Uruchom skrypt:
```bash
python Panorama_Rule_Finder
```
3. Postępuj zgodnie z instrukcjami na ekranie, wprowadzając kryteria wyszukiwania

### 4. Panorama Object Cleanup
Skrypt pomaga w usuwaniu obiektów adresowych z konfiguracji Panorama.

#### Opis
Po podaniu adresu IP skrypt generuje komendę `show | match`, a następnie na podstawie
wyniku w formacie `set` tworzy listę poleceń `delete`. Najpierw proponuje usunięcie
obiektu z reguł (source/destination), później ewentualne skasowanie całych reguł,
usunięcie z grup adresowych, a na końcu usunięcie samego obiektu.

#### Użycie
1. Przygotuj listę adresów IP do sprawdzenia (opcjonalnie):
   - umieść adresy IPv4 (po jednym na linię) w pliku `ip.txt` w katalogu skryptu lub
   - podaj pojedynczy adres poprzez parametr `--ip`.
2. Uruchom skrypt:
```bash
python Panorama_object_cleanup.py [--ip 192.0.2.10] [--ip-file custom_list.txt]
```
3. Jeśli podano plik z adresami, skrypt wyświetli zestaw poleceń `show | match H-adres-32`
   dla każdego obiektu. Skopiuj je i wykonaj na Panoramie, a następnie wklej zbiorczy
   wynik w formacie `set`. Zakończ wklejanie, wpisując w osobnej linii `END`. W
   dowolnym momencie możesz wpisać `q`, aby przerwać działanie skryptu.
4. Po wklejeniu wyniku skrypt przygotuje komendy `delete` dla każdego obiektu z listy.
5. Po obsłudze pliku możesz kontynuować, wpisując kolejne adresy ręcznie lub zakończyć
   działanie, podając `q`.


## Autor

Szymon

## Licencja

MIT 
