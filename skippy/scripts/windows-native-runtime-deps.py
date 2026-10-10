#!/usr/bin/env python3
"""Collect and verify non-system DLL dependencies in Windows native runtimes."""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import struct
import sys


HOST_DLLS = {
    "advapi32.dll",
    "bcrypt.dll",
    "cfgmgr32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "d3d12.dll",
    "dbghelp.dll",
    "dxgi.dll",
    "gdi32.dll",
    "kernel32.dll",
    "msvcp140.dll",
    "msvcrt.dll",
    # NVIDIA deliberately ships the CUDA driver import library with the driver,
    # not the redistributable toolkit. A native CUDA runtime must load it from
    # the host at device-use time, just as Linux CUDA runtimes load libcuda.so.1.
    # Keep cudart/cublas and every other toolkit DLL out of this allowlist: they
    # remain redistributable dependencies that must be packaged.
    "nvcuda.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "secur32.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ucrtbase.dll",
    "user32.dll",
    "version.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "vulkan-1.dll",
    "winmm.dll",
    "ws2_32.dll",
}


class PeFormatError(ValueError):
    """Raised when a file is not a supported PE image."""


def _unpack(data: bytes, fmt: str, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PeFormatError("truncated PE image")
    return struct.unpack_from(fmt, data, offset)


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise PeFormatError("PE import name points outside the image")
    end = data.find(b"\0", offset)
    if end < 0:
        raise PeFormatError("unterminated PE import name")
    return data[offset:end].decode("ascii")


# PE COFF `Machine` values for every architecture native runtimes ship for.
MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64

MACHINE_NAMES = {
    MACHINE_I386: "x86",
    MACHINE_AMD64: "x86_64",
    MACHINE_ARM64: "arm64",
}


def machine_name(machine: int) -> str:
    return MACHINE_NAMES.get(machine, f"0x{machine:04x}")


def _pe_offset(data: bytes, path: pathlib.Path) -> int:
    if data[:2] != b"MZ":
        raise PeFormatError(f"not a PE image: {path}")
    (offset,) = _unpack(data, "<I", 0x3C)
    if data[offset : offset + 4] != b"PE\0\0":
        raise PeFormatError(f"invalid PE signature: {path}")
    return offset


def pe_machine(path: pathlib.Path) -> int:
    """Return the architecture recorded in a PE image's COFF file header."""
    data = path.read_bytes()
    (machine,) = _unpack(data, "<H", _pe_offset(data, path) + 4)
    return machine


def imported_dlls(path: pathlib.Path) -> list[str]:
    data = path.read_bytes()
    pe_offset = _pe_offset(data, path)

    file_header = pe_offset + 4
    (_, section_count, _, _, _, optional_size, _) = _unpack(
        data, "<HHIIIHH", file_header
    )
    optional_header = file_header + 20
    (magic,) = _unpack(data, "<H", optional_header)
    if magic == 0x20B:
        data_directories = optional_header + 112
    elif magic == 0x10B:
        data_directories = optional_header + 96
    else:
        raise PeFormatError(f"unsupported PE optional-header magic 0x{magic:x}: {path}")

    (import_rva, _) = _unpack(data, "<II", data_directories + 8)
    section_table = optional_header + optional_size
    sections: list[tuple[int, int, int]] = []
    for index in range(section_count):
        section = section_table + index * 40
        (virtual_size, virtual_address, raw_size, raw_offset) = _unpack(
            data, "<IIII", section + 8
        )
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset))

    def rva_offset(rva: int) -> int:
        for virtual_address, size, raw_offset in sections:
            if virtual_address <= rva < virtual_address + size:
                return raw_offset + rva - virtual_address
        if rva < len(data):
            return rva
        raise PeFormatError(f"PE RVA 0x{rva:x} is outside every section: {path}")

    if import_rva == 0:
        return []
    descriptor = rva_offset(import_rva)
    imports: list[str] = []
    while True:
        fields = _unpack(data, "<IIIII", descriptor)
        if not any(fields):
            break
        name_rva = fields[3]
        if name_rva == 0:
            raise PeFormatError(f"PE import descriptor has no DLL name: {path}")
        imports.append(_cstring(data, rva_offset(name_rva)))
        descriptor += 20
    return imports


def is_host_dll(name: str) -> bool:
    normalized = name.casefold()
    return (
        normalized in HOST_DLLS
        or normalized.startswith("api-ms-win-")
        or normalized.startswith("ext-ms-win-")
    )


def default_search_dirs() -> list[pathlib.Path]:
    candidates: list[pathlib.Path] = []
    for compiler in ("g++", "gcc"):
        compiler_path = shutil.which(compiler)
        if compiler_path:
            candidates.append(pathlib.Path(compiler_path).parent)
            break
    candidates.extend(
        pathlib.Path(entry)
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry
    )
    vulkan_sdk = os.environ.get("VULKAN_SDK")
    if vulkan_sdk:
        candidates.extend(
            [pathlib.Path(vulkan_sdk) / "Bin", pathlib.Path(vulkan_sdk) / "Bin32"]
        )
    return candidates


def _matches_machine(path: pathlib.Path, expected_machine: int) -> bool:
    try:
        return pe_machine(path) == expected_machine
    except (OSError, PeFormatError):
        return False


def _dll_index(
    directories: list[pathlib.Path], expected_machine: int | None = None
) -> dict[str, pathlib.Path]:
    result: dict[str, pathlib.Path] = {}
    for directory in directories:
        if not directory.is_dir():
            continue
        try:
            entries = directory.iterdir()
        except OSError:
            continue
        for entry in entries:
            if not (entry.is_file() and entry.suffix.casefold() == ".dll"):
                continue
            key = entry.name.casefold()
            if key in result:
                continue
            # A same-named DLL for a different architecture can never satisfy the
            # runtime's imports: LoadLibraryExW rejects it with ERROR_BAD_EXE_FORMAT.
            # Skip it so the search keeps looking for a matching candidate instead
            # of bundling a dependency the runtime cannot load at run time.
            if expected_machine is not None and not _matches_machine(
                entry, expected_machine
            ):
                continue
            result[key] = entry
    return result


def _packaged_dlls(lib_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    return {
        path.name.casefold(): path
        for path in lib_dir.iterdir()
        if path.is_file() and path.suffix.casefold() == ".dll"
    }


def dependency_gaps(
    lib_dir: pathlib.Path, scan_dirs: list[pathlib.Path] | None = None
) -> dict[str, set[str]]:
    packaged = _packaged_dlls(lib_dir)
    gaps: dict[str, set[str]] = {}
    scan_dirs = scan_dirs or [lib_dir]
    libraries = {
        path.name.casefold(): path
        for scan_dir in scan_dirs
        if scan_dir.is_dir()
        for path in scan_dir.iterdir()
        if path.is_file() and path.suffix.casefold() == ".dll"
    }
    for name, library in sorted(libraries.items()):
        missing = {
            dependency
            for dependency in imported_dlls(library)
            if not is_host_dll(dependency) and dependency.casefold() not in packaged
        }
        if missing:
            gaps[name] = missing
    return gaps


def _runtime_machine(
    lib_dir: pathlib.Path, scan_dirs: list[pathlib.Path]
) -> int | None:
    """Architecture of the runtime being packaged, read from its own DLLs."""
    for directory in (lib_dir, *scan_dirs):
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if not (path.is_file() and path.suffix.casefold() == ".dll"):
                continue
            try:
                return pe_machine(path)
            except (OSError, PeFormatError):
                continue
    return None


def collect_dependencies(
    lib_dir: pathlib.Path, search_dirs: list[pathlib.Path], scan_dirs: list[pathlib.Path] | None = None
) -> list[pathlib.Path]:
    expected_machine = _runtime_machine(lib_dir, scan_dirs or [])
    search_index = _dll_index(
        [lib_dir, *search_dirs, *default_search_dirs()], expected_machine
    )
    copied: list[pathlib.Path] = []
    while True:
        gaps = dependency_gaps(lib_dir, scan_dirs)
        if not gaps:
            return copied
        unresolved: dict[str, set[str]] = {}
        for importer, dependencies in gaps.items():
            for dependency in sorted(dependencies):
                source = search_index.get(dependency.casefold())
                if source is None:
                    unresolved.setdefault(importer, set()).add(dependency)
                    continue
                destination = lib_dir / source.name
                if not destination.exists():
                    shutil.copy2(source, destination)
                    copied.append(destination)
        if unresolved:
            details = "; ".join(
                f"{importer}: {', '.join(sorted(dependencies))}"
                for importer, dependencies in sorted(unresolved.items())
            )
            raise RuntimeError(f"unresolved Windows runtime DLL dependencies: {details}")


def runtime_architectures(lib_dir: pathlib.Path) -> dict[int, list[str]]:
    machines: dict[int, list[str]] = {}
    for path in sorted(lib_dir.iterdir()):
        if not (path.is_file() and path.suffix.casefold() == ".dll"):
            continue
        try:
            machine = pe_machine(path)
        except (OSError, PeFormatError):
            continue
        machines.setdefault(machine, []).append(path.name)
    return machines


def verify_architectures(lib_dir: pathlib.Path) -> None:
    machines = runtime_architectures(lib_dir)
    if len(machines) <= 1:
        return
    details = "; ".join(
        f"{machine_name(machine)}: {', '.join(sorted(names))}"
        for machine, names in sorted(machines.items())
    )
    raise RuntimeError(f"mixed-architecture Windows runtime DLLs: {details}")


def verify_dependencies(lib_dir: pathlib.Path, scan_dirs: list[pathlib.Path] | None = None) -> None:
    verify_architectures(lib_dir)
    gaps = dependency_gaps(lib_dir, scan_dirs)
    if not gaps:
        return
    details = "; ".join(
        f"{importer}: {', '.join(sorted(dependencies))}"
        for importer, dependencies in sorted(gaps.items())
    )
    raise RuntimeError(f"unpackaged Windows runtime DLL dependencies: {details}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--lib-dir", type=pathlib.Path, required=True)
    collect.add_argument("--search-dir", type=pathlib.Path, action="append", default=[])
    collect.add_argument("--scan-dir", type=pathlib.Path, action="append", default=[])
    verify = subparsers.add_parser("verify")
    verify.add_argument("--lib-dir", type=pathlib.Path, required=True)
    verify.add_argument("--scan-dir", type=pathlib.Path, action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "collect":
            scan_dirs = [args.lib_dir, *args.scan_dir]
            copied = collect_dependencies(args.lib_dir, args.search_dir, scan_dirs)
            for path in copied:
                print(f"bundled Windows runtime dependency: {path.name}")
        else:
            verify_dependencies(args.lib_dir, [args.lib_dir, *args.scan_dir])
    except (OSError, PeFormatError, RuntimeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
