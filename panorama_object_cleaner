#!/usr/bin/env python3
"""Panorama object cleanup helper script.

This tool assists in removing an address object from Panorama policies and groups.
"""

from __future__ import annotations

import ipaddress
from typing import List, Tuple


def prompt_for_ip() -> str:
    """Ask the user for an IPv4 address and validate it."""

    while True:
        ip_input = input("Podaj adres IP obiektu (np. 192.0.2.10): ").strip()
        if not ip_input:
            print("Adres IP nie może być pusty. Spróbuj ponownie.\n")
            continue
        try:
            ipaddress.IPv4Address(ip_input)
        except ipaddress.AddressValueError:
            print("Nieprawidłowy adres IPv4. Wprowadź adres w formacie xxx.xxx.xxx.xxx.\n")
            continue
        return ip_input


def collect_cli_output(object_name: str) -> List[str]:
    """Collect CLI output pasted by the user."""

    print("\nSkopiuj i uruchom w Panoramie poniższe polecenie, aby wyszukać obiekt:")
    print(f"show | match {object_name}\n")
    print(
        "Następnie skopiuj wynik w formacie 'set' z Panoramy i wklej go poniżej.\n"
        "Po wklejeniu całego wyniku wpisz w osobnej linii END i naciśnij Enter.\n"
    )

    lines: List[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        if line.strip():
            lines.append(line.strip())
    return lines


def _append_unique(container: List[str], command: str) -> None:
    if command not in container:
        container.append(command)


def parse_set_output(object_name: str, lines: List[str]) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Parse set-output lines and build delete commands.

    Returns tuple with commands in order:
    - remove_from_policies
    - delete_policies
    - remove_from_groups
    - delete_object
    """

    remove_from_policies: List[str] = []
    delete_policies: List[str] = []
    remove_from_groups: List[str] = []
    delete_object: List[str] = []

    for raw_line in lines:
        if not raw_line.startswith("set "):
            continue

        tokens = raw_line.split()
        if len(tokens) < 2:
            continue

        if object_name not in tokens:
            continue

        if "security" in tokens and "rules" in tokens:
            # Policy line
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
                _append_unique(remove_from_policies, command)
            else:
                if tokens[-1] != object_name:
                    continue
                command = "delete " + " ".join(path_tokens)
                _append_unique(delete_policies, command)
            continue

        if "address-group" in tokens:
            try:
                member_index = tokens.index("[")
                path_tokens = tokens[1:member_index]
            except ValueError:
                # No brackets -> single member definition
                if tokens[-1] != object_name:
                    continue
                path_tokens = tokens[1:-1]
            if not path_tokens:
                continue
            command = "delete " + " ".join(path_tokens + [object_name])
            _append_unique(remove_from_groups, command)
            continue

        if "address" in tokens:
            addr_index = tokens.index("address")
            if tokens[addr_index + 1] != object_name:
                continue
            path_tokens = tokens[1 : addr_index + 2]
            if not path_tokens:
                continue
            command = "delete " + " ".join(path_tokens)
            _append_unique(delete_object, command)
            continue

    return remove_from_policies, delete_policies, remove_from_groups, delete_object


def print_commands(
    remove_from_policies: List[str],
    delete_policies: List[str],
    remove_from_groups: List[str],
    delete_object: List[str],
) -> None:
    print("\nGotowe. Poniżej znajduje się lista komend do usunięcia obiektu:")

    if not any((remove_from_policies, delete_policies, remove_from_groups, delete_object)):
        print("Brak komend do wyświetlenia. Sprawdź czy wkleiłeś poprawny output.")
        return

    if remove_from_policies:
        print("\n# 1. Usuń obiekt z reguł (source/destination):")
        for cmd in remove_from_policies:
            print(cmd)

    if delete_policies:
        print("\n# 2. Usuń całe reguły, w których obiekt był jedynym elementem:")
        for cmd in delete_policies:
            print(cmd)

    if remove_from_groups:
        print("\n# 3. Usuń obiekt z grup adresowych:")
        for cmd in remove_from_groups:
            print(cmd)

    if delete_object:
        print("\n# 4. Usuń sam obiekt adresowy:")
        for cmd in delete_object:
            print(cmd)



def main() -> None:
    ip = prompt_for_ip()
    object_name = f"H-{ip}-32"
    lines = collect_cli_output(object_name)
    results = parse_set_output(object_name, lines)
    print_commands(*results)


if __name__ == "__main__":
    main()
