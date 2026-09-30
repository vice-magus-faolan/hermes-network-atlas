# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic text/Markdown/Mermaid from stored evidence, never fabricated links."""
from __future__ import annotations

from datetime import datetime
import html
import os
from pathlib import Path
import tempfile

from .config import Policy
from .query import device_detail
from .storage import Store, identifier, private_directory, timestamp, utc_now


def markdown(value: object) -> str:
    """Escape HTML, Markdown delimiters, pipes, backticks and hostile control text."""
    parts = []
    for char in str(value):
        if not char.isprintable():
            parts.append(f"&#92;u{ord(char):04x}")
        elif char in "\\|`*_[]{}<>#!~":
            parts.append(f"&#{ord(char)};")
        else:
            parts.append(html.escape(char, quote=True))
    return "".join(parts)


def mermaid(value: object) -> str:
    """Mermaid numeric entities contain punctuation; no raw quotes/directives/newlines."""
    return "".join(char if char.isalnum() or char == " " else f"#{ord(char)};" for char in str(value))


def _plain(value: object) -> str:
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in str(value))


def _field(device: dict, field: str, default: str = "unknown") -> str:
    fact = device["fields"].get(field)
    if fact and fact["conflict"]:
        return "conflicting " + field
    return str(fact["value"]) if fact else default


def _node(device: dict) -> str:
    # IDs originate in native code. Do not use names, hostnames, or source text as identifiers.
    return "n" + device["id"].replace("-", "")


def _addresses(device: dict, policy: Policy) -> str:
    if not policy.include_addresses:
        return "omitted by policy"
    addresses = []
    for interface in device["interfaces"]:
        for address in interface["addresses"]:
            if address["current"]:
                marker = " (ownership conflict)" if address["ownership_conflict"] else ""
                addresses.append(address["address"] + marker)
    return ", ".join(sorted(set(addresses))) or "unknown"


def _access(device: dict) -> str:
    authorized = [entry["alias"] for entry in device["access"] if entry["authorized_for_atlas_ssh_inspection"]]
    result = "Atlas SSH inspection authorized: " + ", ".join(authorized) if authorized else "not authorized by this profile"
    conflicts = _alias_conflicts(device)
    if conflicts:
        result += "; SSH alias identity unresolved: " + ", ".join(conflicts)
    return result


def _alias_conflicts(device: dict) -> list[str]:
    return sorted({entry["alias"] for entry in device["access"] if entry["ambiguous_association"]})


def _uncertain(device: dict) -> bool:
    return (any(field["conflict"] for field in device["fields"].values())
            or bool(_alias_conflicts(device))
            or any(item["identity_uncertain"] for item in device["interfaces"])
            or any(address["ownership_conflict"] for interface in device["interfaces"] for address in interface["addresses"]))


def _state(device: dict) -> str:
    state = device["status"] + ("; uncertain" if _uncertain(device) else "")
    if _alias_conflicts(device):
        state += "; ambiguous alias association"
    return state


def _provenance(device: dict) -> str:
    categories = {entry["confidence"] for fact in device["fields"].values() for entry in fact["evidence"]}
    return ",".join(sorted(categories)) or "unknown"


def _edges(devices: list[dict]) -> list[dict]:
    edges = {relation["id"]: relation for device in devices for relation in device["relationships"]}
    return [edges[key] for key in sorted(edges)]


def _edge_label(edge: dict) -> str:
    fact = edge["facts"].get("relationship")
    if fact is None:
        raise ValueError("relationship lacks provenance")
    confidences = sorted({entry["confidence"] for entry in fact["evidence"]})
    endpoints = ":" + edge["source_interface"] if edge["source_interface"] else ""
    endpoints += " -> :" + edge["target_interface"] if edge["target_interface"] else ""
    return edge["relationship_type"] + " [" + ",".join(confidences) + "]" + endpoints


def _render(devices: list[dict], policy: Policy) -> dict[str, str]:
    by_id = {device["id"]: device for device in devices}
    edges = _edges(devices)
    linked = {edge[key] for edge in edges for key in ("source_device", "target_device")}
    text = ["Network Atlas — stored knowledge, not live reachability", ""]
    md = ["# Network Atlas", "", "Stored knowledge only. Authorization is not reachability. Unknown links remain unknown.", "",
          "| Device (stable ID) | Type | Address | Status | Provenance | Access |", "| --- | --- | --- | --- | --- | --- |"]
    mm = ["graph TD"]
    for device in devices:
        name = _field(device, "canonical_name", device["id"])
        state = _state(device)
        state += "; isolated (no supported relations)" if device["id"] not in linked else ""
        label = name + " [" + state + "; " + _provenance(device) + "]"
        text.append(_plain(label + " | " + _addresses(device, policy) + " | " + _access(device)))
        md.append("| " + " | ".join(markdown(value) for value in
                  (name + " (" + device["id"] + ")", _field(device, "device_type"), _addresses(device, policy), state, _provenance(device), _access(device))) + " |")
        mm.append(f'  {_node(device)}["{mermaid(label)}"]')
        if policy.include_interfaces:
            _interface_lines(md, text, device)
    md.extend(("", "## Supported relationships", ""))
    for edge in edges:
        if edge["source_device"] not in by_id or edge["target_device"] not in by_id:
            raise ValueError("incomplete topology snapshot")
        _edge_lines(md, text, mm, edge, by_id)
    if not edges:
        md.append("No supported relationships recorded. All devices are isolated.")
        text.append("No supported relationships recorded.")
    mm.append("  %% Edges are stored assertions/evidence; never a reachability claim.")
    return {"text": "\n".join(text) + "\n", "markdown": "\n".join(md) + "\n", "mermaid": "\n".join(mm) + "\n"}


def _interface_lines(md: list, text: list, device: dict) -> None:
    for interface in device["interfaces"]:
        field = interface["fields"].get("name")
        name = field["value"] if field and not field["conflict"] else "unknown/conflicting"
        line = "Interface " + str(name) + " (" + interface["id"] + "): " + str(interface["mac_address"] or "unknown MAC")
        md.append("\n" + markdown(line) + "\n")
        text.append("  " + _plain(line))


def _edge_lines(md: list, text: list, mm: list, edge: dict, devices: dict) -> None:
    source, target = devices[edge["source_device"]], devices[edge["target_device"]]
    label = _edge_label(edge)
    line = _field(source, "canonical_name", source["id"]) + " -- " + label + " --> " + _field(target, "canonical_name", target["id"])
    md.append("- " + markdown(line))
    text.append(_plain(line))
    fact = edge["facts"]["relationship"]
    uncertain = fact["conflict"] or any(entry["confidence"] == "inferred" for entry in fact["evidence"])
    arrow = "-.->" if uncertain else "-->"
    mm.append(f'  {_node(source)} {arrow}|"{mermaid(label)}"| {_node(target)}')


def render_map(policy: Policy, *, now: datetime | None = None) -> dict[str, str]:
    """Render the complete bounded snapshot; refuse overflow rather than hide edges."""
    clock = now or utc_now()
    devices = []
    if policy.database.exists():
        with Store(policy) as store, store.snapshot():
            rows = store.connection.execute("SELECT * FROM devices ORDER BY id LIMIT ?", (policy.limits.observations + 1,)).fetchall()
            if len(rows) > policy.limits.observations:
                raise ValueError("map device bound exceeded")
            devices = [device_detail(store, row, clock) for row in rows]
    outputs = _render(devices, policy)
    if any(len(content.encode("utf-8")) > policy.limits.output_bytes for content in outputs.values()):
        raise ValueError("map output exceeds configured byte bound")
    return outputs


def _stage(path: Path, content: str) -> Path:
    if path.is_symlink():
        raise ValueError("symlink export refused")
    fd, temporary = tempfile.mkstemp(prefix=".atlas-export-", dir=path.parent)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return Path(temporary)


def export_map(policy: Policy, outputs: dict[str, str], *, now: datetime | None = None) -> list[str]:
    """Write only two fixed profile-local generated files; each replace is atomic.

    SQLite remains authoritative. A filesystem interruption between two replaces
    can leave mismatched generated files; rerun export to repair them. No timestamp
    appears in generated content. Explicit exports are audited locally.
    """
    private_directory(policy.exports)
    os.chmod(policy.exports, 0o700)
    with Store(policy, writable=True) as store, store.transaction():
        store.audit(identifier(), "map_export_requested", "local_render", timestamp(now or utc_now()),
                    details={"files": ["network_map.md", "network_map.mmd"]})
    destinations = [(policy.exports / "network_map.md", outputs["markdown"]),
                    (policy.exports / "network_map.mmd", outputs["mermaid"])]
    staged = []
    try:
        for path, content in destinations:
            staged.append((path, _stage(path, content)))
        for path, temporary in staged:
            os.replace(temporary, path)
        with Store(policy, writable=True) as store, store.transaction():
            store.audit(identifier(), "map_exported", "local_render", timestamp(now or utc_now()),
                        details={"files": [path.name for path, _ in destinations]})
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)
    return [str(path) for path, _ in destinations]
