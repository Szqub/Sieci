"""Hardened HTTPS transport shared by the legacy Panorama utilities."""

import os
from typing import Optional, Union

import requests
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


MAX_XML_RESPONSE_BYTES = 512 * 1024 * 1024
DEFAULT_TIMEOUT = (10.0, 300.0)


class PanoramaHTTPSClient:
    """POST-only PAN-OS XML transport that never places credentials in URLs."""

    def __init__(self, panorama_host, verify_tls=None):
        self.base_url = "https://{}/api/".format(panorama_host)
        ca_bundle = os.environ.get("PANORAMA_CA_BUNDLE")
        if verify_tls is None:
            self.verify = ca_bundle if ca_bundle else False
        else:
            self.verify = verify_tls
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "ByteTech-Panorama-Legacy/2.0"})
        if self.verify is False:
            print(
                "OSTRZEŻENIE: weryfikacja certyfikatu TLS Panoramy jest wyłączona. "
                "Ustaw PANORAMA_CA_BUNDLE, aby użyć firmowego CA."
            )

    @staticmethod
    def _parse_xml(payload):
        try:
            return SafeET.fromstring(
                payload,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except (SafeET.ParseError, DefusedXmlException) as exc:
            raise RuntimeError("Panorama zwróciła niebezpieczny albo niepoprawny XML.") from exc

    def _post(self, data, api_key=None):
        headers = {"X-PAN-KEY": api_key} if api_key else {}
        response = self.session.post(
            self.base_url,
            data=data,
            headers=headers,
            verify=self.verify,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        try:
            if 300 <= response.status_code < 400:
                raise RuntimeError(
                    "Panorama zwróciła redirect; przerwano, aby nie przekazać poświadczeń."
                )
            response.raise_for_status()
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > MAX_XML_RESPONSE_BYTES:
                raise RuntimeError("Odpowiedź XML Panoramy przekracza limit 512 MiB.")
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_XML_RESPONSE_BYTES:
                    raise RuntimeError("Odpowiedź XML Panoramy przekracza limit 512 MiB.")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            response.close()

    def authenticate(self, username, password):
        payload = self._post(
            {"type": "keygen", "user": username, "password": password}
        )
        root = self._parse_xml(payload)
        if root.get("status") != "success":
            message = " ".join(
                value.strip() for value in root.itertext() if value and value.strip()
            )
            raise RuntimeError(
                "Uwierzytelnianie Panoramy nie powiodło się: {}".format(message[:300])
            )
        key = root.findtext(".//key")
        if not key or not key.strip():
            raise RuntimeError("Panorama nie zwróciła klucza API.")
        return key.strip()

    def get_config(self, xpath, api_key):
        payload = self._post(
            {"type": "config", "action": "get", "xpath": xpath},
            api_key=api_key,
        )
        root = self._parse_xml(payload)
        if root.get("status") == "error":
            message = " ".join(
                value.strip() for value in root.itertext() if value and value.strip()
            )
            raise RuntimeError("Panorama zwróciła błąd: {}".format(message[:300]))
        return SafeET.tostring(root, encoding="unicode")

    def close(self):
        self.session.headers.pop("X-PAN-KEY", None)
        self.session.close()
