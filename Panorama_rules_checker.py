#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skrypt do sprawdzania hit count dla reguł w Palo Alto Networks Panorama

Autor: Szymon
Data: 11.03.2025

Opis:
Skrypt służy do weryfikacji hit count dla reguł zdefiniowanych w pliku wejściowym
w systemie Palo Alto Networks Panorama. Dla każdej reguły sprawdzany jest hit count
i w zależności od wyniku, reguła jest zapisywana do odpowiedniego pliku wyjściowego.

Format danych wejściowych:
nazwa_reguly
  gdzie:
    - nazwa_reguly - pełna nazwa reguły w Panoramie

Format danych wyjściowych:
rules_0hit - zawiera reguły z hit count = 0
rules_hit - zawiera reguły z hit count > 0
"""

import getpass
import sys
from netmiko import ConnectHandler
import re

class PanoramaSSH:
    """
    Klasa do obsługi połączenia SSH z Palo Alto Networks Panorama.
    Udostępnia metody do pobierania danych o regułach.
    """
    def __init__(self, panorama_ip, username, password):
        self.panorama_ip = panorama_ip
        self.username = username
        self.password = password
        self.device = {
            'device_type': 'paloalto_panos',
            'ip': panorama_ip,
            'username': username,
            'password': password,
            'port': 22,
            'verbose': True,
            'global_delay_factor': 2
        }
        self.connection = None

    def connect(self):
        try:
            print(f"DEBUG: Próba połączenia SSH z {self.panorama_ip}")
            self.connection = ConnectHandler(**self.device)
            print("DEBUG: Pomyślnie nawiązano połączenie SSH")
            
            # Wyłącz pager
            print("DEBUG: Wyłączanie pagera...")
            self.connection.send_command('set cli pager off')
            
            # Poczekaj na znak zachęty
            print("DEBUG: Oczekiwanie na znak zachęty...")
            self.connection.send_command('', expect_string='>')
            
            return True
        except Exception as e:
            print(f"BŁĄD: Podczas łączenia z Panoramą: {e}")
            return False

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
                print("DEBUG: Pomyślnie zamknięto połączenie SSH")
            except Exception as e:
                print(f"BŁĄD: Podczas zamykania połączenia: {e}")

    def get_device_groups(self):
        try:
            print("DEBUG: Pobieranie listy device groups...")
            output = self.connection.send_command('show devicegroups')
            
            # Zapisz odpowiedź do pliku dla debugowania
            with open('debug_device_groups.txt', 'w') as f:
                f.write(output)
            print("DEBUG: Zapisano odpowiedź do pliku debug_device_groups.txt")
            
            # Parsowanie outputu CLI - szukamy tylko linii z "Group:"
            device_groups = []
            for line in output.splitlines():
                if 'Group:' in line:
                    # Wyciągamy nazwę grupy po "Group:" i przed "Shared"
                    group_name = line.split('Group:')[1].split('Shared')[0].strip()
                    device_groups.append(group_name)
            
            print(f"DEBUG: Znaleziono {len(device_groups)} device groups")
            return device_groups
        except Exception as e:
            print(f"BŁĄD: Podczas pobierania device groups: {e}")
            return None

    def get_rulebases(self, device_group):
        # Zwracamy tylko pre i post rulebase
        return ['pre-rulebase', 'post-rulebase']

    def get_rule_hit_count(self, device_group, rulebase, rule_name):
        try:
            print(f"DEBUG: Pobieranie hit count dla reguły {rule_name}...")
            command = f'show rule-hit-count device-group {device_group} {rulebase} security rules rule-name {rule_name}'
            output = self.connection.send_command(command)
            
            # Zapisz odpowiedź do pliku dla debugowania
            with open('debug_hit_count_response.txt', 'w') as f:
                f.write(output)
            print("DEBUG: Zapisano odpowiedź do pliku debug_hit_count_response.txt")
            print("DEBUG: Pełna odpowiedź:")
            print(output)
            
            # Szukaj hit count dla każdego urządzenia
            total_hit_count = 0
            for line in output.splitlines():
                if 'vsys' in line.lower():  # Pomijamy nagłówek
                    continue
                if line.strip() and not line.startswith('---'):  # Pomijamy puste linie i separatory
                    # Szukamy liczby między vsys7 a pierwszym "-"
                    hit_count_match = re.search(r'vsys\d+\s+(\d+)\s+-', line)
                    if hit_count_match:
                        device_hit_count = int(hit_count_match.group(1))
                        total_hit_count += device_hit_count
                        print(f"DEBUG: Znaleziono hit count {device_hit_count} dla urządzenia w linii: {line}")
            
            print(f"DEBUG: Sumaryczny hit count dla wszystkich urządzeń: {total_hit_count}")
            return total_hit_count
            
        except Exception as e:
            print(f"BŁĄD: Podczas pobierania hit count dla reguły {rule_name}: {e}")
            return None

def main():
    print("Skrypt sprawdzania hit count dla reguł w Palo Alto Panorama")
    print("==========================================================")
    
    # Pobierz dane logowania
    panorama_ip = "IP PANORAMY"
    username = input("Podaj nazwę użytkownika: ")
    password = getpass.getpass("Podaj hasło: ")
    
    # Inicjalizacja połączenia SSH
    panorama = PanoramaSSH(panorama_ip, username, password)
    
    print("\nŁączenie z Panoramą...")
    if not panorama.connect():
        print("Nie udało się połączyć z Panoramą. Sprawdź dane logowania.")
        sys.exit(1)
    
    try:
        # Pobierz listę device groups
        print("\nPobieranie listy device groups...")
        device_groups = panorama.get_device_groups()
        if not device_groups:
            print("Nie udało się pobrać listy device groups.")
            sys.exit(1)
        
        print("\nDostępne device groups:")
        for i, group in enumerate(device_groups, 1):
            print(f"{i}. {group}")
        
        # Wybór device group
        while True:
            try:
                choice = int(input("\nWybierz numer device group: "))
                if 1 <= choice <= len(device_groups):
                    selected_device_group = device_groups[choice-1]
                    break
                else:
                    print(f"Błędny numer. Podaj wartość od 1 do {len(device_groups)}.")
            except ValueError:
                print("Podaj poprawny numer.")
        
        # Pobierz listę rulebases
        print(f"\nPobieranie listy rulebases dla device group {selected_device_group}...")
        rulebases = panorama.get_rulebases(selected_device_group)
        if not rulebases:
            print("Nie udało się pobrać listy rulebases.")
            sys.exit(1)
        
        print("\nDostępne rulebases:")
        for i, rulebase in enumerate(rulebases, 1):
            print(f"{i}. {rulebase}")
        
        # Wybór rulebase
        while True:
            try:
                choice = int(input("\nWybierz numer rulebase: "))
                if 1 <= choice <= len(rulebases):
                    selected_rulebase = rulebases[choice-1]
                    break
                else:
                    print(f"Błędny numer. Podaj wartość od 1 do {len(rulebases)}.")
            except ValueError:
                print("Podaj poprawny numer.")
        
        # Wczytaj nazwy reguł z pliku
        input_file = input("\nPodaj ścieżkę do pliku z nazwami reguł: ")
        try:
            with open(input_file, 'r') as file:
                rules = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"Błąd podczas wczytywania pliku: {e}")
            sys.exit(1)
        
        if not rules:
            print("Plik jest pusty lub nie zawiera reguł.")
            sys.exit(1)
        
        print(f"\nZnaleziono {len(rules)} reguł do sprawdzenia.")
        
        # Sprawdź hit count dla każdej reguły
        rules_0hit = []
        rules_hit = []
        rules_not_found = []
        
        for rule in rules:
            print(f"\nSprawdzanie reguły: {rule}")
            hit_count = panorama.get_rule_hit_count(selected_device_group, selected_rulebase, rule)
            if hit_count is not None:
                if hit_count == 0:
                    rules_0hit.append(rule)
                    print(f"Hit count = 0")
                else:
                    rules_hit.append(rule)
                    print(f"Hit count = {hit_count}")
            else:
                rules_not_found.append(rule)
                print(f"Nie udało się pobrać hit count dla reguły {rule}")
        
        # Zapisz wyniki do plików
        try:
            with open('rules_0hit', 'w') as f:
                for rule in rules_0hit:
                    f.write(f"{rule}\n")
            print(f"\nZapisano {len(rules_0hit)} reguł z hit count = 0 do pliku rules_0hit")
            
            with open('rules_hit', 'w') as f:
                for rule in rules_hit:
                    f.write(f"{rule}\n")
            print(f"Zapisano {len(rules_hit)} reguł z hit count > 0 do pliku rules_hit")
            
            if rules_not_found:
                with open('rules_not_found', 'w') as f:
                    for rule in rules_not_found:
                        f.write(f"{rule}\n")
                print(f"Zapisano {len(rules_not_found)} reguł, których nie znaleziono w rulebase do pliku rules_not_found")
        except Exception as e:
            print(f"BŁĄD podczas zapisywania wyników: {e}")
            print("\nWyniki do ręcznego skopiowania:")
            print("\nReguły z hit count = 0:")
            for rule in rules_0hit:
                print(rule)
            print("\nReguły z hit count > 0:")
            for rule in rules_hit:
                print(rule)
            if rules_not_found:
                print("\nReguły, których nie znaleziono w rulebase:")
                for rule in rules_not_found:
                    print(rule)
    finally:
        # Zawsze zamykamy połączenie
        panorama.disconnect()

if __name__ == "__main__":
    main() 