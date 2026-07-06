"""Tests for binary reverse engineering analyzer."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ==========================================================================
# extract_strings — no lief required, test with real bytes
# ==========================================================================

class TestExtractStrings:
    def test_extracts_ascii_strings(self, tmp_path: Path) -> None:
        data = b"Hello\x00World\x00\x00\x01\x02TestString123\x00"
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        from secagent.analyzers.binary_analyzer import extract_strings
        result = extract_strings(str(f))
        assert "TestString123" in result
        assert "Hello" in result
        assert "World" in result

    def test_min_length_filter(self, tmp_path: Path) -> None:
        data = b"AB\x00CDEF\x00GHIJKLMNO\x00"
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        from secagent.analyzers.binary_analyzer import extract_strings
        result = extract_strings(str(f), min_length=4)
        # "AB" is too short, "CDEF" is exactly 4, "GHIJKLMNO" is long
        assert "GHIJKLMNO" in result

    def test_limit(self, tmp_path: Path) -> None:
        data = b"A" * 1000 + b"TARGET" + b"B" * 1000
        f = tmp_path / "test.bin"
        f.write_bytes(data)
        from secagent.analyzers.binary_analyzer import extract_strings
        result = extract_strings(str(f), limit=3)
        assert len(result) <= 3

    def test_missing_file_returns_empty(self) -> None:
        from secagent.analyzers.binary_analyzer import extract_strings
        result = extract_strings("/nonexistent/path/file.bin")
        assert result == []


# ==========================================================================
# detect_packing — mock lief
# ==========================================================================

class TestDetectPacking:
    def _make_fake_binary(self, section_names: list[str]):
        binary = MagicMock()
        binary.sections = [MagicMock(name=n) for n in section_names]
        return binary

    def test_detects_upx_section(self) -> None:
        from secagent.analyzers.binary_analyzer import detect_packing
        binary = self._make_fake_binary(["UPX0", ".text", ".data"])
        with patch("lief.parse", return_value=binary), \
             patch("secagent.analyzers.binary_analyzer.Path") as mp:
            mp.return_value.read_bytes.return_value = b"\x00" * 100
            result = detect_packing("fake.exe")
        assert result["packed"] is True
        assert result["packer"] == "UPX"

    def test_no_packer_clean_binary(self) -> None:
        from secagent.analyzers.binary_analyzer import detect_packing
        binary = self._make_fake_binary([".text", ".data", ".rdata"])
        with patch("lief.parse", return_value=binary), \
             patch("secagent.analyzers.binary_analyzer.Path") as mp:
            mp.return_value.read_bytes.return_value = b"\x00" * 100
            result = detect_packing("clean.exe")
        assert result["packed"] is False
        assert result["packer"] is None

    def test_handles_parse_failure(self) -> None:
        from secagent.analyzers.binary_analyzer import detect_packing
        with patch("lief.parse", side_effect=Exception("bad")):
            result = detect_packing("bad.exe")
        assert result["packed"] is False


# ==========================================================================
# analyze_binary — mock lief to avoid needing real binaries
# ==========================================================================

class TestAnalyzeBinary:
    def _make_mock_pe(self):
        binary = MagicMock()
        binary.architecture = MagicMock()
        binary.architecture.__str__ = lambda self: "<Architecture:x86>"
        binary.entrypoint = 0x401000
        binary.sections = [
            MagicMock(name=".text", virtual_address=0x401000, size=0x1000),
            MagicMock(name=".data", virtual_address=0x402000, size=0x200),
        ]
        sym1 = MagicMock()
        sym1.name = "VirtualAlloc"
        sym1.library.name = "kernel32.dll"
        sym2 = MagicMock()
        sym2.name = "MessageBoxA"
        sym2.library.name = "user32.dll"
        binary.imported_libraries = ["kernel32.dll", "user32.dll"]
        binary.imported_symbols = [sym1, sym2]
        binary.exported_functions = [MagicMock(name="main")]
        binary.symbols = [MagicMock(name="main"), MagicMock(name="init")]
        binary.optional_header.dll_characteristics = 0x8140
        binary.has_signatures = False
        return binary

    def test_analyze_pe(self) -> None:
        from secagent.analyzers.binary_analyzer import analyze_binary
        binary = self._make_mock_pe()
        with patch("lief.parse", return_value=binary):
            result = analyze_binary("fake.exe")
        assert result["format"] == "PE"
        assert result["architecture"] == "x86"
        assert result["entrypoint"] == 0x401000
        assert len(result["sections"]) == 2
        assert result["sections"][0]["name"] == ".text"

    def test_security_features_pe(self) -> None:
        from secagent.analyzers.binary_analyzer import analyze_binary
        binary = self._make_mock_pe()
        with patch("lief.parse", return_value=binary):
            result = analyze_binary("fake.exe")
        sec = result["security"]
        assert sec["nx"] is True
        assert sec["aslr"] is True
        assert sec["cfg"] is True
        assert sec["dep"] is True

    def test_unsupported_format(self) -> None:
        from secagent.analyzers.binary_analyzer import analyze_binary
        with patch("lief.parse", return_value=None):
            result = analyze_binary("not_a_binary.txt")
        assert "error" in result

    def test_parse_exception(self) -> None:
        from secagent.analyzers.binary_analyzer import analyze_binary
        with patch("lief.parse", side_effect=RuntimeError("boom")):
            result = analyze_binary("bad.bin")
        assert "error" in result


# ==========================================================================
# disassemble_function — mock lief + capstone
# ==========================================================================

class TestDisassembleFunction:
    def test_disasm_returns_instructions(self) -> None:
        from secagent.analyzers.binary_analyzer import disassemble_function
        binary = MagicMock()
        binary.architecture = MagicMock()
        binary.architecture.__str__ = lambda self: "<Architecture:x86_64>"
        binary.entrypoint = 0x401000
        binary.symbols = []
        binary.get_content_from_virtual_address.return_value = bytes([0x55, 0x48, 0x89, 0xE5])

        insn = MagicMock()
        insn.address = 0x401000
        insn.bytes = b"\x55"
        insn.mnemonic = "push"
        insn.op_str = "rbp"

        cs_mock = MagicMock()
        cs_mock.disasm.return_value = [insn]

        with patch("lief.parse", return_value=binary), \
             patch("capstone.Cs", return_value=cs_mock):
            result = disassemble_function("fake.exe", count=1)
        assert len(result) == 1
        assert result[0]["mnemonic"] == "push"
        assert result[0]["address"] == 0x401000

    def test_disasm_by_symbol(self) -> None:
        from secagent.analyzers.binary_analyzer import disassemble_function
        binary = MagicMock()
        binary.architecture = MagicMock()
        binary.architecture.__str__ = lambda self: "<Architecture:x86_64>"
        binary.entrypoint = 0x401000
        sym = MagicMock()
        sym.name = "my_func"
        sym.value = 0x402000
        binary.symbols = [sym]
        binary.get_content_from_virtual_address.return_value = b""

        with patch("lief.parse", return_value=binary):
            result = disassemble_function("fake.exe", symbol="my_func")
        assert result == [{"error": "No code bytes at 0x402000"}]

    def test_disasm_symbol_not_found(self) -> None:
        from secagent.analyzers.binary_analyzer import disassemble_function
        binary = MagicMock()
        binary.architecture = MagicMock()
        binary.architecture.__str__ = lambda self: "<Architecture:x86_64>"
        binary.entrypoint = 0x401000
        binary.symbols = [MagicMock(name="other", value=0x401000)]
        with patch("lief.parse", return_value=binary):
            result = disassemble_function("fake.exe", symbol="missing")
        assert result == [{"error": "Symbol 'missing' not found"}]

    def test_disasm_parse_error(self) -> None:
        from secagent.analyzers.binary_analyzer import disassemble_function
        with patch("lief.parse", return_value=None):
            result = disassemble_function("fake.exe")
        assert result == [{"error": "Unsupported or corrupted binary"}]
