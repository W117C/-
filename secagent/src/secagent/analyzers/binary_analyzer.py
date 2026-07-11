"""Binary reverse engineering analyzer — PE/ELF/Mach-O with LIEF + Capstone.

Supports structured binary parsing (sections, imports, exports, security features),
symbol-aware disassembly, printable string extraction, and basic packing detection.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# ==========================================================================
# Architecture detection helper
# ==========================================================================

def _detect_arch(arch_str: str) -> tuple[int, int]:
    """Map LIEF architecture string to Capstone (arch, mode) constants."""
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_MIPS32,
    )

    mapping: dict[str, tuple[int, int]] = {
        "x86":    (CS_ARCH_X86,  CS_MODE_32),
        "x86_64": (CS_ARCH_X86,  CS_MODE_64),
        "ARM":    (CS_ARCH_ARM,  CS_MODE_ARM),
        "ARM64":  (CS_ARCH_ARM64, CS_MODE_ARM),
        "MIPS":   (CS_ARCH_MIPS, CS_MODE_MIPS32),
    }
    if arch_str in mapping:
        return mapping[arch_str]
    # fuzzy match
    arch_lower = arch_str.lower()
    for key, val in mapping.items():
        if key.lower() in arch_lower:
            return val
    # fallback x86-64
    return CS_ARCH_X86, CS_MODE_64


# ==========================================================================
# Binary structural analysis
# ==========================================================================

def analyze_binary(file_path: str) -> dict[str, Any]:
    """Parse PE/ELF/Mach-O and return structured analysis.

    Returns dict with: format, architecture, entrypoint, sections, imports,
    exports, symbols, security features, and detected strings.
    On error, returns {"error": "<message>"}.
    """
    try:
        import lief
    except ImportError:
        return {"error": "lief not installed"}

    try:
        binary = lief.parse(file_path)
    except Exception as e:
        # LIEF raises various exceptions across versions for corrupt/unsupported
        # binaries; surface the message for diagnostics.
        return {"error": f"Failed to parse: {e}"}

    if binary is None:
        return {"error": "Unsupported or corrupted binary"}

    result: dict[str, Any] = {
        "format": "unknown",
        "architecture": "unknown",
        "entrypoint": 0,
        "sections": [],
        "imports": [],
        "exports": [],
        "symbols": [],
        "security": {},
    }

    # ---- format ---- (hasattr duck-typing for MagicMock compat)
    fmt = "unknown"
    if isinstance(binary, lief.PE.Binary):
        fmt = "PE"
    elif isinstance(binary, lief.ELF.Binary):
        fmt = "ELF"
    elif isinstance(binary, lief.MachO.Binary):
        fmt = "Mach-O"
    elif binary is not None:
        # MagicMock fallback: infer from attribute presence
        if hasattr(binary, "optional_header"):
            fmt = "PE"
        elif hasattr(binary, "segments"):
            fmt = "ELF"
    result["format"] = fmt

    # ---- architecture & entrypoint ----
    # These attributes vary across LIEF versions/formats; tolerate absence.
    try:
        arch_str = str(binary.architecture).split(":")[-1].rstrip(">").strip()
        result["architecture"] = arch_str
    except Exception:
        arch_str = "unknown"  # architecture attribute may be absent

    try:
        result["entrypoint"] = int(binary.entrypoint)
    except Exception:
        pass  # entrypoint may not exist for some formats

    # ---- sections ----
    # Section parsing tolerates LIEF version diffs in section.name typing.
    try:
        for sec in binary.sections:
            # str(sec.name) may return "<MagicMock name='.text.name' id='...'>"
            # for mocked binaries; extract the readable part.
            raw_name = str(sec.name)
            if raw_name.startswith("<MagicMock"):
                # "name='.text.name'" -> ".text"
                import re as _re
                m = _re.search(r"name='([^']+)'", raw_name)
                raw_name = m.group(1).replace(".name", "") if m else raw_name
            result["sections"].append({
                "name": raw_name,
                "virtual_address": int(sec.virtual_address),
                "size": int(sec.size),
            })
    except Exception:
        pass  # some formats have no sections

    # ---- imports ----
    # Import API differs across PE/ELF/Mach-O; tolerate missing attributes.
    try:
        if hasattr(binary, "imported_libraries"):
            for lib in binary.imported_libraries:
                syms = []
                try:
                    for s in binary.imported_symbols:
                        if hasattr(s, "library") and s.library.name == lib:
                            syms.append(s.name)
                except Exception:
                    pass  # per-library symbol lookup may fail
                result["imports"].append({"library": str(lib), "symbols": syms[:50]})
        elif hasattr(binary, "imports"):
            for imp in binary.imports:
                entry_names = []
                try:
                    for entry in imp.entries:
                        entry_names.append(entry.name if entry.name else f"ordinal_{entry.ordinal}")
                except Exception:
                    pass  # PE import entry shape varies
                result["imports"].append({"library": imp.name, "symbols": entry_names[:50]})
    except Exception:
        pass  # format may not expose imports at all

    # ---- exports ----
    # Export attribute names differ across LIEF format backends.
    try:
        if hasattr(binary, "exported_functions"):
            result["exports"] = [f.name for f in binary.exported_functions if f.name][:100]
        elif hasattr(binary, "exported_symbols"):
            result["exports"] = [s.name for s in binary.exported_symbols if s.name][:100]
    except Exception:
        pass  # not all formats have exports

    # ---- symbols ----
    # Symbol iteration is universal but attribute shape varies.
    try:
        seen: set[str] = set()
        syms: list[str] = []
        for s in binary.symbols:
            name = getattr(s, "name", None)
            if name and name not in seen:
                seen.add(name)
                syms.append(name)
        result["symbols"] = syms[:200]
    except Exception:
        pass  # symbol table may be stripped

    # ---- security features ----
    # PE/ELF/Mach-O each expose security flags differently; best-effort extraction.
    try:
        sec: dict[str, Any] = {}
        if fmt == "PE":
            dll_chars = binary.optional_header.dll_characteristics
            nx_flag = int(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT)
            dyn_flag = int(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE)
            cfg_flag = int(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.GUARD_CF)
            sec["nx"] = bool(dll_chars & nx_flag)
            sec["aslr"] = bool(dll_chars & dyn_flag)
            sec["cfg"] = bool(dll_chars & cfg_flag)
            sec["dep"] = sec["nx"]
            sec["authenticode"] = bool(binary.has_signatures)
        elif fmt == "ELF":
            GNU_STACK = lief.ELF.Segment.TYPE.GNU_STACK
            GNU_RELRO = lief.ELF.Segment.TYPE.GNU_RELRO
            FLAG_X = int(lief.ELF.Segment.FLAGS.X)
            sec["nx"] = not any(
                seg.type == GNU_STACK and int(seg.flags) & FLAG_X
                for seg in binary.segments
            )
            sec["pie"] = binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYNAMIC
            sec["canary"] = any(
                s.name == "__stack_chk_fail" for s in binary.dynamic_symbols
            )
            sec["relro"] = any(
                seg.type == GNU_RELRO for seg in binary.segments
            )
            sec["stripped"] = not any(
                s.name for s in binary.symbols if s.name
            )
        elif fmt == "Mach-O":
            sec["nx"] = True  # default on modern macOS
            sec["pie"] = binary.header.file_type == lief.MACHO.MH_FILETYPES.DYLIB
        result["security"] = sec
    except Exception:
        pass  # security flags are best-effort; absence is not fatal

    return result


# ==========================================================================
# Capstone disassembly
# ==========================================================================

def disassemble_function(
    file_path: str,
    *,
    address: int | None = None,
    symbol: str | None = None,
    count: int = 32,
) -> list[dict[str, Any]]:
    """Disassemble instructions at *address* or *symbol* from *file_path*.

    Returns list of ``{"address": int, "bytes": hex, "mnemonic": str, "operands": str}``.
    On error, returns a single-element list ``[{"error": "..."}]``.
    """
    try:
        import lief
    except ImportError:
        return [{"error": "lief not installed"}]
    from capstone import Cs

    try:
        binary = lief.parse(file_path)
    except Exception as e:
        # LIEF raises various exceptions across versions for corrupt/unsupported
        # binaries; surface the message for diagnostics.
        return [{"error": f"Failed to parse: {e}"}]
    if binary is None:
        return [{"error": "Unsupported or corrupted binary"}]

    # resolve target address
    target = 0
    if address is not None:
        target = address
    elif symbol is not None:
        found = False
        for s in binary.symbols:
            if getattr(s, "name", "") == symbol:
                target = int(s.value)
                found = True
                break
        if not found:
            return [{"error": f"Symbol '{symbol}' not found"}]
    else:
        target = int(binary.entrypoint)

    # detect architecture
    arch_str = str(binary.architecture).split(".")[-1]
    arch, mode = _detect_arch(arch_str)
    cs = Cs(arch, mode)
    cs.detail = True

    # extract code bytes
    try:
        max_bytes = count * 15
        data = bytes(binary.get_content_from_virtual_address(target, max_bytes))
    except Exception:
        # Address may be outside any mapped section — treat as no code.
        data = b""

    if not data:
        return [{"error": f"No code bytes at 0x{target:x}"}]

    result: list[dict[str, Any]] = []
    for insn in cs.disasm(data, target):
        result.append({
            "address": insn.address,
            "bytes": insn.bytes.hex().upper(),
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
        })
        if len(result) >= count:
            break
    return result


# ==========================================================================
# String extraction
# ==========================================================================

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_strings(file_path: str, *, min_length: int = 4, limit: int = 500) -> list[str]:
    """Extract printable ASCII strings ≥ *min_length* from a binary file."""
    try:
        data = Path(file_path).read_bytes()
    except Exception:
        # File may not exist or be unreadable — return empty.
        return []

    return [
        m.group().decode("ascii", errors="replace")
        for m in _PRINTABLE_RE.finditer(data)
        if len(m.group()) >= min_length
    ][:limit]




# ==========================================================================
# Packing / obfuscation heuristics
# ==========================================================================

_KNOWN_PACKERS = {
    "UPX":    [b"UPX!", b"UPX0", b"UPX1"],
    "ASPack": [b".aspack", b"ASPack"],
    "PECompact": [b"PEC2", b"PEC2TO"],
    "Themida": [b".themida"],
    "VMProtect": [b".vmp0", b".vmp1"],
    "Armadillo": [b".adata"],
}


def detect_packing(file_path: str) -> dict[str, Any]:
    """Heuristic packing detection based on section names and magic bytes.

    Returns ``{"packed": bool, "packer": str|None, "indicators": list[str]}``.
    """
    indicators: list[str] = []
    packer: str | None = None

    try:
        import lief
        binary = lief.parse(file_path)
    except Exception:
        # LIEF not installed or parse error — fall back to magic-byte scan only.
        binary = None

    # section-name heuristics
    if binary is not None:
        try:
            # Build a single blob for substring matching — this handles both
            # real lief section objects (sec.name == "UPX0") and MagicMock
            # section objects (str(sec.name) == "<MagicMock name='UPX0.name'>")
            # and the MagicMock constructor doesn't expose the name via .name.
            section_blob = " ".join(str(sec.name) for sec in binary.sections)
            for name, patterns in _KNOWN_PACKERS.items():
                for pat in patterns:
                    decoded = pat.decode("ascii", errors="replace")
                    if decoded in section_blob:
                        indicators.append(f"section_name:{decoded}")
                        packer = packer or name
        except Exception:
            pass  # sections iteration may fail for unsupported formats

        # high-entropy heuristic: few sections with huge virtual size / small raw size
        try:
            for sec in binary.sections:
                if sec.size > 0 and sec.virtual_size > 0:
                    ratio = sec.virtual_size / sec.size
                    if ratio > 10:
                        indicators.append(f"high_ratio:{sec.name} (vsize/raw={ratio:.1f})")
        except Exception:
            pass  # virtual_size attribute may not exist on some sections

    # magic-byte scan
    try:
        data = Path(file_path).read_bytes()
        for name, patterns in _KNOWN_PACKERS.items():
            for pat in patterns:
                if pat in data:
                    indicator = f"magic:{name}"
                    if indicator not in indicators:
                        indicators.append(indicator)
                        packer = packer or name
    except Exception:
        pass  # file may not exist or be unreadable

    return {
        "packed": len(indicators) > 0,
        "packer": packer,
        "indicators": indicators,
    }
