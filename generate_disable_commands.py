#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skrypt do generowania poleceń CLI do wyłączenia reguł w Palo Alto Networks Panorama

Autor: Szymon
Data: 11.03.2025

Opis:
Skrypt generuje polecenia CLI do wyłączenia reguł zdefiniowanych w pliku wejściowym.
Polecenia są zapisywane do pliku rules_disable_cli_pa.txt z podziałem na grupy po 30 reguł.

Format danych wejściowych:
nazwa_reguly
  gdzie:
    - nazwa_reguly - pełna nazwa reguły w Panoramie

Format danych wyjściowych:
set device-group NAZWA_DG pre/post-rulebase security rules "NAZWA_REGULY" disabled yes
"""

def main():
    print("Generator poleceń CLI do wyłączenia reguł w Palo Alto Panorama")
    print("=============================================================")
    
    # Pobierz dane od użytkownika
    device_group = input("Podaj nazwę Device Group: ")
    while True:
        rulebase = input("Podaj rulebase (pre/post): ").lower()
        if rulebase in ['pre', 'post']:
            break
        print("Błędna wartość. Podaj 'pre' lub 'post'.")
    
    # Wczytaj nazwy reguł z pliku
    input_file = input("\nPodaj ścieżkę do pliku z nazwami reguł: ")
    try:
        with open(input_file, 'r') as file:
            rules = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Błąd podczas wczytywania pliku: {e}")
        return
    
    if not rules:
        print("Plik jest pusty lub nie zawiera reguł.")
        return
    
    print(f"\nZnaleziono {len(rules)} reguł do wyłączenia.")
    
    # Generuj polecenia CLI
    commands = []
    for rule in rules:
        command = f'set device-group {device_group} {rulebase}-rulebase security rules "{rule}" disabled yes'
        commands.append(command)
    
    # Zapisz polecenia do pliku z podziałem na grupy po 30
    try:
        with open('rules_disable_cli_pa.txt', 'w') as f:
            for i, command in enumerate(commands, 1):
                f.write(command + '\n')
                if i % 30 == 0 and i < len(commands):
                    f.write('\n')  # Dodaj pustą linię co 30 poleceń
        print(f"\nZapisano {len(commands)} poleceń do pliku rules_disable_cli_pa.txt")
    except Exception as e:
        print(f"BŁĄD podczas zapisywania poleceń: {e}")
        print("\nPolecenia do ręcznego skopiowania:")
        for i, command in enumerate(commands, 1):
            print(command)
            if i % 30 == 0 and i < len(commands):
                print()

if __name__ == "__main__":
    main() 