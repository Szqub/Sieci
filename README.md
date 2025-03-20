# Panorama Rules Checker

Skrypt do sprawdzania hit count dla reguł w Palo Alto Networks Panorama.

## Opis

Skrypt służy do weryfikacji hit count dla reguł zdefiniowanych w pliku wejściowym w systemie Palo Alto Networks Panorama. Dla każdej reguły sprawdzany jest hit count i w zależności od wyniku, reguła jest zapisywana do odpowiedniego pliku wyjściowego.

## Wymagania

- Python 3.6+
- Moduły:
  - requests
  - xml.etree.ElementTree
  - getpass

## Instalacja

1. Sklonuj repozytorium:
```bash
git clone https://github.com/twoj-username/panorama-rules-checker.git
cd panorama-rules-checker
```

2. Zainstaluj wymagane moduły:
```bash
pip install -r requirements.txt
```

## Użycie

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

## Format danych

### Wejściowy
```
nazwa_reguly
```
gdzie:
- nazwa_reguly - pełna nazwa reguły w Panoramie

### Wyjściowy
Skrypt tworzy dwa pliki:
- `rules_0hit` - zawierający reguły z zerowym hit count
- `rules_hit` - zawierający reguły z hit count większym od zera

## Autor

Szymon

## Licencja

MIT 