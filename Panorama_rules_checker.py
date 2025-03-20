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

import requests
import getpass
import xml.etree.ElementTree as ET
import sys
from urllib3.exceptions import InsecureRequestWarning

# Wyłączenie ostrzeżeń o niezweryfikowanym certyfikacie SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class PanoramaAPI:
    """
    Klasa do obsługi API Palo Alto Networks Panorama.
    Udostępnia metody do uwierzytelniania oraz pobierania danych o regułach.
    """
    def __init__(self, panorama_ip, username, password):
        self.panorama_ip = panorama_ip
        self.username = username
        self.password = password
        self.api_key = None
        self.base_url = f"https://{self.panorama_ip}/api/"

    def get_api_key(self):
        params = {
            'type': 'keygen',
            'user': self.username,
            'password': self.password
        }
        
        try:
            print(f"DEBUG: Próba uwierzytelnienia użytkownika {self.username} na {self.panorama_ip}")
            response = requests.get(self.base_url, params=params, verify=False)
            print(f"DEBUG: Otrzymano odpowiedź HTTP {response.status_code}")
            response.raise_for_status()
            
            root = ET.fromstring(response.text)
            status = root.get('status')
            print(f"DEBUG: Status uwierzytelniania: {status}")
            
            if status == 'success':
                key_element = root.find('.//key')
                if key_element is not None:
                    self.api_key = key_element.text
                    print("DEBUG: Pomyślnie pobrano klucz API")
                    return True
                else:
                    print("BŁĄD: Brak elementu <key> w odpowiedzi")
                    return False
            else:
                error_msg = root.find('.//msg')
                if error_msg is not None:
                    print(f"BŁĄD: Uwierzytelnianie nie powiodło się: {error_msg.text}")
                else:
                    print("BŁĄD: Uwierzytelnianie nie powiodło się bez szczegółowej wiadomości")
                return False
        except Exception as e:
            print(f"BŁĄD: Podczas uzyskiwania klucza API: {e}")
            print(f"DEBUG: Pełna treść błędu: {str(e)}")
            return False

    def get_device_groups(self):
        if not self.api_key:
            print("Brak klucza API. Najpierw należy wywołać get_api_key().")
            return None
        
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': "/config/devices/entry/device-group",
            'key': self.api_key
        }
        
        try:
            print("DEBUG: Pobieranie listy device groups...")
            response = requests.get(self.base_url, params=params, verify=False)
            response.raise_for_status()
            print(f"DEBUG: Otrzymano odpowiedź HTTP {response.status_code}")
            
            root = ET.fromstring(response.text)
            device_groups = []
            for entry in root.findall('.//device-group/entry'):
                device_groups.append(entry.get('name'))
            
            print(f"DEBUG: Znaleziono {len(device_groups)} device groups")
            return device_groups
        except Exception as e:
            print(f"BŁĄD: Podczas pobierania device groups: {e}")
            print(f"DEBUG: Pełna treść błędu: {str(e)}")
            return None

    def get_rulebases(self, device_group):
        if not self.api_key:
            print("Brak klucza API. Najpierw należy wywołać get_api_key().")
            return None
        
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': f"/config/devices/entry/device-group/entry[@name='{device_group}']/pre-rulebase/security/rules",
            'key': self.api_key
        }
        
        try:
            print(f"DEBUG: Pobieranie rulebases dla device group {device_group}...")
            response = requests.get(self.base_url, params=params, verify=False)
            response.raise_for_status()
            print(f"DEBUG: Otrzymano odpowiedź HTTP {response.status_code}")
            
            root = ET.fromstring(response.text)
            rulebases = []
            for entry in root.findall('.//entry'):
                rulebases.append(entry.get('name'))
            
            print(f"DEBUG: Znaleziono {len(rulebases)} rulebases")
            return rulebases
        except Exception as e:
            print(f"BŁĄD: Podczas pobierania rulebases: {e}")
            print(f"DEBUG: Pełna treść błędu: {str(e)}")
            return None

    def get_rule_hit_count(self, device_group, rulebase, rule_name):
        if not self.api_key:
            print("Brak klucza API. Najpierw należy wywołać get_api_key().")
            return None
        
        params = {
            'type': 'op',
            'cmd': f'<show><rule-hit-count><device-group><entry name="{device_group}"/></device-group><rulebase><entry name="{rulebase}"/></rulebase><rule-list><member>{rule_name}</member></rule-list></rule-hit-count></show>',
            'key': self.api_key
        }
        
        try:
            print(f"DEBUG: Pobieranie hit count dla reguły {rule_name}...")
            response = requests.get(self.base_url, params=params, verify=False)
            response.raise_for_status()
            print(f"DEBUG: Otrzymano odpowiedź HTTP {response.status_code}")
            
            root = ET.fromstring(response.text)
            hit_count = root.find('.//hit-count')
            if hit_count is not None:
                return int(hit_count.text)
            return 0
        except Exception as e:
            print(f"BŁĄD: Podczas pobierania hit count dla reguły {rule_name}: {e}")
            print(f"DEBUG: Pełna treść błędu: {str(e)}")
            return None

def main():
    print("Skrypt sprawdzania hit count dla reguł w Palo Alto Panorama")
    print("==========================================================")
    
    # Pobierz dane logowania
    panorama_ip = "IP PANORAMY"
    username = input("Podaj nazwę użytkownika: ")
    password = getpass.getpass("Podaj hasło: ")
    
    # Inicjalizacja API
    panorama = PanoramaAPI(panorama_ip, username, password)
    
    print("\nŁączenie z Panoramą...")
    if not panorama.get_api_key():
        print("Nie udało się uzyskać klucza API. Sprawdź dane logowania.")
        sys.exit(1)
    
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
    except Exception as e:
        print(f"BŁĄD podczas zapisywania wyników: {e}")
        print("\nWyniki do ręcznego skopiowania:")
        print("\nReguły z hit count = 0:")
        for rule in rules_0hit:
            print(rule)
        print("\nReguły z hit count > 0:")
        for rule in rules_hit:
            print(rule)

if __name__ == "__main__":
    main() 