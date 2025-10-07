#!/usr/bin/env python3
"""Panorama object cleanup helper script.

This tool assists in removing address objects from Panorama policies and groups.
"""

from __future__ import annotations

import ipaddress
from argparse import ArgumentParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional


def prompt_for_ip() -> Optional[str]:
    """Ask the user for an IPv4 address and validate it.

    Returns ``None`` when the user chooses to quit.
    """

    while True:
        ip_input = input("Podaj adres IP obiektu (np. 192.0.2.10) lub 'q' aby zakończyć: ").strip()
        if ip_input == "q":
            return None
        if not ip_input:
            print("Adres IP nie może być pusty. Spróbuj ponownie.\n")
            continue
        try:
            ipaddress.IPv4Address(ip_input)
        except ipaddress.AddressValueError:
            print("Nieprawidłowy adres IPv4. Wprowadź adres w formacie xxx.xxx.xxx.xxx.\n")
            continue
        return ip_input


def collect_cli_output(object_names: List[str]) -> Optional[List[str]]:
    """Collect CLI output pasted by the user for one or more objects.

    Returns ``None`` when the user chooses to quit.
    """

    print("\nSkopiuj i uruchom w Panoramie poniższe polecenie lub zestaw poleceń:")
    if len(object_names) == 1:
        print(f"show | match {object_names[0]}\n")
    else:
        for object_name in object_names:
            print(f"show | match {object_name}")
        print()

    print(
        "Następnie skopiuj wynik w formacie 'set' z Panoramy i wklej go poniżej.\n"
        "Po wklejeniu całego wyniku wpisz w osobnej linii END i naciśnij Enter.\n"
        "Aby zakończyć działanie skryptu, wpisz 'q'.\n"
    )

    lines: List[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        stripped = line.strip()
        if stripped == "q":
            return None
        if stripped == "END":
            break
        if stripped:
            lines.append(stripped)
    return lines


def _append_unique(container: List[str], command: str) -> None:
    if command not in container:
        container.append(command)


def parse_set_output(
    object_names: Iterable[str], lines: List[str]
) -> Dict[str, Dict[str, List[str]]]:
    """Parse set-output lines and build delete commands for multiple objects."""

    object_list = list(object_names)
    commands: Dict[str, Dict[str, List[str]]] = {
        name: {
            "remove_from_policies": [],
            "delete_policies": [],
            "remove_from_groups": [],
            "delete_object": [],
        }
        for name in object_list
    }
    object_set = set(object_list)

    for raw_line in lines:
        if not raw_line.startswith("set "):
            continue

        tokens = raw_line.split()
        if len(tokens) < 2:
            continue

        matching_objects = list(dict.fromkeys(token for token in tokens if token in object_set))
        if not matching_objects:
            continue

        for object_name in matching_objects:
            if "security" in tokens and "rules" in tokens:
                context = None
                for candidate in ("source", "destination"):
                    if candidate in tokens:
                        context = candidate
                        break
                if context is None:
                    continue
                context_index = tokens.index(context)
                path_tokens = tokens[1:context_index]
                if not path_tokens:
                    continue
                if "[" in tokens:
                    command = "delete " + " ".join(path_tokens + [context, object_name])
                    _append_unique(commands[object_name]["remove_from_policies"], command)
                else:
                    if tokens[-1] != object_name:
                        continue
                    command = "delete " + " ".join(path_tokens)
                    _append_unique(commands[object_name]["delete_policies"], command)
                continue

            if "address-group" in tokens:
                try:
                    member_index = tokens.index("[")
                    path_tokens = tokens[1:member_index]
                except ValueError:
                    if tokens[-1] != object_name:
                        continue
                    path_tokens = tokens[1:-1]
                if not path_tokens:
                    continue
                command = "delete " + " ".join(path_tokens + [object_name])
                _append_unique(commands[object_name]["remove_from_groups"], command)
                continue

            if "address" in tokens:
                addr_index = tokens.index("address")
                if addr_index + 1 >= len(tokens) or tokens[addr_index + 1] != object_name:
                    continue
                path_tokens = tokens[1 : addr_index + 2]
                if not path_tokens:
                    continue
                command = "delete " + " ".join(path_tokens)
                _append_unique(commands[object_name]["delete_object"], command)
                continue

    return commands


def print_commands(object_names: Iterable[str], commands: Dict[str, Dict[str, List[str]]]) -> None:
    print("\nGotowe. Poniżej znajduje się lista komend do usunięcia obiektów:")

    any_command = any(
        commands.get(object_name, {}).get(category)
        for object_name in object_names
        for category in (
            "remove_from_policies",
            "delete_policies",
            "remove_from_groups",
            "delete_object",
        )
    )
    if not any_command:
        print("Brak komend do wyświetlenia. Sprawdź czy wkleiłeś poprawny output.")
        return

    for object_name in object_names:
        object_commands = commands.get(object_name)
        if not object_commands:
            continue

        print(f"\n=== {object_name} ===")

        if not any(object_commands.values()):
            print("Brak komend dla tego obiektu.")
            continue

        if object_commands["remove_from_policies"]:
            print("\n# 1. Usuń obiekt z reguł (source/destination):")
            for cmd in object_commands["remove_from_policies"]:
                print(cmd)

        if object_commands["delete_policies"]:
            print("\n# 2. Usuń całe reguły, w których obiekt był jedynym elementem:")
            for cmd in object_commands["delete_policies"]:
                print(cmd)

        if object_commands["remove_from_groups"]:
            print("\n# 3. Usuń obiekt z grup adresowych:")
            for cmd in object_commands["remove_from_groups"]:
                print(cmd)

        if object_commands["delete_object"]:
            print("\n# 4. Usuń sam obiekt adresowy:")
            for cmd in object_commands["delete_object"]:
                print(cmd)


def load_ips_from_file(path: Path) -> List[str]:
    """Load IPv4 addresses from a text file."""

    if not path.exists():
        return []

    ips: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            ipaddress.IPv4Address(stripped)
        except ipaddress.AddressValueError:
            print(f"Pominięto nieprawidłowy adres IPv4 w pliku {path}: {stripped}")
            continue
        ips.append(stripped)
    return ips



def main() -> None:
    parser = ArgumentParser(description="Panorama object cleanup helper")
    parser.add_argument("--ip", dest="ip", help="Adres IP obiektu do usunięcia")
    parser.add_argument(
        "--ip-file",
        dest="ip_file",
        default="ip.txt",
        help="Plik z listą adresów IP do przetworzenia (domyślnie ip.txt)",
    )
    args = parser.parse_args()

    pending_ips: List[str] = []
    seen_ips = set()

    if args.ip:
        try:
            ipaddress.IPv4Address(args.ip)
        except ipaddress.AddressValueError:
            parser.error("Podano nieprawidłowy adres IPv4 w parametrze --ip.")
        pending_ips.append(args.ip)
        seen_ips.add(args.ip)

    ip_file_path = Path(args.ip_file)
    file_ips = load_ips_from_file(ip_file_path) if args.ip_file else []
    for ip in file_ips:
        if ip not in seen_ips:
            pending_ips.append(ip)
            seen_ips.add(ip)

    if file_ips:
        print(
            f"Załadowano {len(file_ips)} adresów IP z pliku {ip_file_path}."
        )

    while True:
        if pending_ips:
            batch_ips = pending_ips.copy()
            pending_ips.clear()
            object_names = [f"H-{ip}-32" for ip in batch_ips]
        else:
            ip = prompt_for_ip()
            if ip is None:
                print("Zakończono działanie skryptu.")
                break
            object_names = [f"H-{ip}-32"]

        lines = collect_cli_output(object_names)
        if lines is None:
            print("Zakończono działanie skryptu.")
            break

        results = parse_set_output(object_names, lines)
        print_commands(object_names, results)


if __name__ == "__main__":
    main()
