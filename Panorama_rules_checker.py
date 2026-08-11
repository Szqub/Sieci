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
import re
import sys
import time

import paramiko


MAX_CLI_RESPONSE_BYTES = 16 * 1024 * 1024

def cli_quote(value):
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Nazwa CLI zawiera niedozwolony znak sterujący.")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


class PanoramaSSH:
    """
    Klasa do obsługi połączenia SSH z Palo Alto Networks Panorama.
    Udostępnia metody do pobierania danych o regułach.
    """
    def __init__(self, panorama_ip, username, password):
        self.panorama_ip = panorama_ip
        self.username = username
        self.password = password
        self.client = None
        self.channel = None

    def connect(self):
        try:
            print(f"DEBUG: Próba połączenia SSH z {self.panorama_ip}")
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
            self.client.connect(
                self.panorama_ip,
                username=self.username,
                password=self.password,
                allow_agent=False,
                look_for_keys=False,
                timeout=10,
                auth_timeout=15,
                banner_timeout=15,
            )
            self.channel = self.client.invoke_shell()
            self._read_until_prompt()
            self.send_command("set cli pager off")
            self.password = None
            print("DEBUG: Pomyślnie nawiązano połączenie SSH")
            return True
        except Exception as exc:
            print(f"BŁĄD: Podczas łączenia z Panoramą: {type(exc).__name__}")
            self.disconnect()
            return False

    def _read_until_prompt(self, timeout=30):
        if self.channel is None:
            raise RuntimeError("Kanał SSH nie jest otwarty.")
        deadline = time.monotonic() + timeout
        output = ""
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                output += self.channel.recv(65535).decode("utf-8", errors="replace")
                if len(output.encode("utf-8")) > MAX_CLI_RESPONSE_BYTES:
                    raise RuntimeError("Odpowiedź CLI przekroczyła bezpieczny limit 16 MiB.")
                if output.rstrip().endswith((">", "#")):
                    return output
            elif self.channel.closed:
                raise RuntimeError("Kanał SSH został zamknięty.")
            time.sleep(0.1)
        raise TimeoutError("Timeout oczekiwania na prompt Panoramy.")

    def send_command(self, command):
        if "\r" in command or "\n" in command:
            raise ValueError("Komenda SSH zawiera niedozwolony znak nowej linii.")
        if self.channel is None:
            raise RuntimeError("Kanał SSH nie jest otwarty.")
        self.channel.send(command + "\n")
        return self._read_until_prompt()

    def disconnect(self):
        try:
            if self.channel is not None:
                self.channel.close()
            if self.client is not None:
                self.client.close()
            print("DEBUG: Pomyślnie zamknięto połączenie SSH")
        except Exception as exc:
            print(f"BŁĄD: Podczas zamykania połączenia: {type(exc).__name__}")
        finally:
            self.channel = None
            self.client = None
            self.password = None

    def get_device_groups(self):
        try:
            print("DEBUG: Pobieranie listy device groups...")
            output = self.send_command('show devicegroups')
            
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
            command = (
                'show rule-hit-count device-group {} {} security rules rule-name {}'.format(
                    cli_quote(device_group), rulebase, cli_quote(rule_name)
                )
            )
            output = self.send_command(command)
            
            # Szukaj hit count dla każdego urządzenia
            total_hit_count = 0
            for line in output.splitlines():
                if line.strip() and not line.startswith('---'):  # Pomijamy puste linie i separatory
                    # Szukamy hit countu używając nowego wyrażenia regularnego
                    hit_count_match = re.search(r'^\s*([\w-]+)\s+\w+\s+(\d+)', line)
                    if hit_count_match:
                        device_name = hit_count_match.group(1)
                        device_hit_count = int(hit_count_match.group(2))
                        total_hit_count += device_hit_count
                        print(f"DEBUG: Znaleziono hit count {device_hit_count} dla urządzenia {device_name} w linii: {line}")
            
            print(f"DEBUG: Sumaryczny hit count dla wszystkich urządzeń: {total_hit_count}")
            return total_hit_count
            
        except Exception as e:
            print(f"BŁĄD: Podczas pobierania hit count dla reguły {rule_name}: {e}")
            return None

def main():
    print("Skrypt sprawdzania hit count dla reguł w Palo Alto Panorama")
    print("==========================================================")
    
    # Pobierz dane logowania
    panorama_ip = input("Podaj hostname lub adres IP Panoramy: ").strip()
    if not panorama_ip or any(character.isspace() or ord(character) < 32 for character in panorama_ip):
        print("Niepoprawny hostname lub adres IP Panoramy.")
        sys.exit(2)
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
            with open(input_file, 'r', encoding='utf-8') as file:
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
            with open('rules_0hit', 'w', encoding='utf-8') as f:
                for rule in rules_0hit:
                    f.write(f"{rule}\n")
            print(f"\nZapisano {len(rules_0hit)} reguł z hit count = 0 do pliku rules_0hit")
            
            with open('rules_hit', 'w', encoding='utf-8') as f:
                for rule in rules_hit:
                    f.write(f"{rule}\n")
            print(f"Zapisano {len(rules_hit)} reguł z hit count > 0 do pliku rules_hit")
            
            if rules_not_found:
                with open('rules_not_found', 'w', encoding='utf-8') as f:
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