"""Placeholder identities and conservative paths; never inspect the filesystem."""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from moonlight.minimizer.models import PrivacyContext, RedactionEvent

# Trusted literals only. Unknown basenames, extensions and arguments are private.
PUBLIC_SEGMENTS = frozenset(
    {
        "windows",
        "system32",
        "syswow64",
        "program files",
        "program files (x86)",
        "programdata",
        "users",
        "appdata",
        "local",
        "locallow",
        "roaming",
        "temp",
        "cache",
        "logs",
        "downloads",
        "documents",
        "desktop",
        "pictures",
        "music",
        "videos",
        "public",
        "bin",
        "usr",
        "home",
        "tmp",
        "var",
    }
)
PUBLIC_EXECUTABLES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "conhost.exe",
        "python.exe",
        "pythonw.exe",
        "explorer.exe",
        "svchost.exe",
        "msiexec.exe",
    }
)
PUBLIC_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".sys",
        ".bin",
        ".log",
        ".tmp",
        ".cache",
        ".zip",
        ".msi",
        ".txt",
        ".pdf",
        ".docx",
        ".xlsx",
        ".pptx",
        ".jpg",
        ".png",
        ".mp4",
        ".json",
        ".db",
        ".sqlite3",
        ".ps1",
        ".py",
    }
)
PUBLIC_FLAGS = frozenset(
    {
        "-noprofile",
        "-noninteractive",
        "-encodedcommand",
        "-enc",
        "-file",
        "-executionpolicy",
        "-windowstyle",
        "--help",
        "--version",
        "-c",
        "-m",
    }
)
TRUNCATION_MARKER = "[TRUNCATED]"


def folded(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


class Redactor:
    def __init__(self, context: PrivacyContext) -> None:
        self.events: list[RedactionEvent] = []
        self.identities: dict[str, str] = {}
        self.tokens: dict[str, dict[str, str]] = {}
        self.private_values: set[str] = set()
        for value in sorted(context.usernames, key=folded):
            self.register_user(value)
        for value in sorted(context.hostnames, key=folded):
            self.register_host(value)

    def event(self, location: str, operation: str, category: str) -> None:
        # Operation values originate only in this module and the projector.
        self.events.append(
            RedactionEvent.model_validate(
                {
                    "location": location,
                    "operation": operation,
                    "category": category,
                }
            )
        )

    def token(self, category: str, value: str, location: str) -> str:
        mapping = self.tokens.setdefault(category, {})
        key = folded(value)
        if key not in mapping:
            mapping[key] = f"{category}_{len(mapping) + 1}"
        result = mapping[key]
        self.events.append(
            RedactionEvent(
                location=location,
                operation="replace",
                category=category,
                placeholder=result,
            )
        )
        return result

    def register_user(self, value: str) -> None:
        if not value:
            return
        # Even a delimiter-only alias must participate in the final leak guard.
        self.private_values.add(folded(value))
        parts = re.split(r"[\\/@]", value)
        user = parts[-1] if "@" not in value else parts[0]
        if user:
            self.private_values.update((folded(value), folded(user)))
            placeholder = self.token("USER", user, "context")
            self.identities.setdefault(folded(user), placeholder)
            self.identities.setdefault(folded(value), placeholder)
        for host in parts[:-1] if "@" not in value else parts[1:]:
            self.register_host(host)

    def register_host(self, value: str) -> None:
        if value:
            self.private_values.add(folded(value))
            try:
                address = ipaddress.ip_address(value.split("%", 1)[0].strip("[]"))
            except ValueError:
                category, key = "HOST", value
            else:
                category = "PUBLIC_IP" if address.is_global else "INTERNAL_IP"
                key = str(address)
            self.identities.setdefault(
                folded(value), self.token(category, key, "context")
            )

    def discover_path(self, value: str) -> None:
        parts = re.split(r"[\\/]+", value)
        for index, part in enumerate(parts[:-1]):
            if folded(part) in {"users", "home"}:
                self.register_user(parts[index + 1])
        if value.startswith(("\\\\", "//")):
            nonempty = [part for part in parts if part]
            if nonempty:
                self.register_host(nonempty[0])

    def atom(self, value: str, location: str) -> str:
        key = folded(value)
        if key in self.identities:
            result = self.identities[key]
            self.events.append(
                RedactionEvent(
                    location=location,
                    operation="replace",
                    category=result.rsplit("_", 1)[0],
                    placeholder=result,
                )
            )
            return result
        if key in PUBLIC_SEGMENTS | PUBLIC_EXECUTABLES and not any(
            private in key for private in self.private_values
        ):
            return key
        suffix_match = re.search(r"\.[a-zA-Z0-9]+$", value)
        suffix = suffix_match.group().casefold() if suffix_match else ""
        extension = (
            suffix
            if suffix in PUBLIC_EXTENSIONS
            and not any(private in suffix for private in self.private_values)
            else ""
        )
        return self.token("PATH", value, location) + extension

    def path(self, value: str, location: str) -> str:
        parts = re.split(r"[\\/]+", value)
        output: list[str] = []
        for part in parts:
            if not part:
                continue
            if part in {".", ".."}:
                output.append(part)
                continue
            if re.fullmatch(r"[A-Za-z]:", part):
                output.append(self.token("VOLUME", part, location))
            else:
                output.append(self.atom(part, location))
        return "/".join(output) or self.token("PATH", value, location)

    def address(self, value: str, location: str) -> tuple[str, str]:
        try:
            address = ipaddress.ip_address(value.split("%", 1)[0].strip("[]"))
        except ValueError:
            self.register_host(value)
            return self.token("HOST", value, location), "hostname"
        scope = "public" if address.is_global else "internal"
        # Canonicalize equivalent IPv6 spellings; zone identifiers are withheld.
        category = "PUBLIC_IP" if scope == "public" else "INTERNAL_IP"
        return self.token(category, str(address), location), scope

    def argument(self, value: str, location: str) -> str:
        if folded(value) in self.identities:
            return self.atom(value, location)
        if folded(value) in PUBLIC_FLAGS | PUBLIC_EXECUTABLES and not any(
            private in folded(value) for private in self.private_values
        ):
            return folded(value)
        if re.match(r"^(?:[A-Za-z]:[\\/]|[\\/])", value):
            return self.path(value, location)
        try:
            ipaddress.ip_address(value.split("%", 1)[0].strip("[]"))
        except ValueError:
            return self.token("ARG", value, location)
        return self.address(value, location)[0]

    def command(
        self, value: list[str], location: str, limit: int
    ) -> dict[str, str | bool]:
        rendered = [self.argument(arg, location) for arg in value]
        text = " ".join(rendered)
        source_length = sum(len(arg) for arg in value) + max(0, len(value) - 1)
        truncated = len(text) > limit or source_length > limit
        if truncated:
            # Preserve whole tokens rather than cutting a placeholder in half.
            parts: list[str] = []
            for word in rendered:
                if len(" ".join((*parts, word, TRUNCATION_MARKER))) > limit:
                    break
                parts.append(word)
            text = " ".join((*parts, TRUNCATION_MARKER))
            self.event(location, "truncate", "command_line")
        return {"text": text, "truncated": truncated}
