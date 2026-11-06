"""Bounded structural validation for an XLSX package, without execution.

This does not sanitize formulas, external links, or embedded content.
"""

import struct
import zipfile
import zlib
from pathlib import PurePosixPath

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from .workflows import WorkflowError

MAX_ENTRIES = 2048
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_XML_BYTES = 1024 * 1024
MAX_DIRECTORY_BYTES = 2 * 1024 * 1024
CONTENT_TYPES = "{http://schemas.openxmlformats.org/package/2006/content-types}"
WORKBOOK = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}workbook"
RELATIONSHIPS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
OFFICE_DOCUMENT = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)
XLSX_MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"


def _check_directory(path):
    """Bound the ZIP central directory before ZipFile loads its entries."""
    with path.open("rb") as source:
        source.seek(0, 2)
        size = source.tell()
        source.seek(max(0, size - 65557))
        tail = source.read()
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise WorkflowError("missing XLSX central directory")
    _, disk, directory_disk, disk_count, count, directory_size, offset, comment = (
        struct.unpack_from("<4s4H2LH", tail, position)
    )
    end_offset = size - len(tail) + position
    if (
        position + 22 + comment != len(tail)
        or disk != 0
        or directory_disk != 0
        or disk_count != count
        or not 0 < count <= MAX_ENTRIES
        or directory_size > MAX_DIRECTORY_BYTES
        or offset + directory_size > end_offset
    ):
        raise WorkflowError("unsupported or oversized XLSX central directory")
    return count


def _xml(package, name):
    info = package.getinfo(name)
    if info.file_size > MAX_XML_BYTES:
        raise WorkflowError("XLSX structural XML exceeds limit")
    payload = package.read(info).decode("utf-8-sig")
    if "<!DOCTYPE" in payload.upper() or "<!ENTITY" in payload.upper():
        raise WorkflowError("XLSX structural XML has a prohibited declaration")
    return ElementTree.fromstring(
        payload, forbid_dtd=True, forbid_entities=True, forbid_external=True
    )


def validate_xlsx(path, max_bytes):
    """Validate package structure and CRCs under explicit resource limits."""
    try:
        expected_entries = _check_directory(path)
        with zipfile.ZipFile(path) as package:
            entries = package.infolist()
            names = [item.filename for item in entries]
            if len(entries) != expected_entries or len(set(names)) != len(names):
                raise WorkflowError("invalid XLSX package entries")
            if sum(item.file_size for item in entries) > min(
                MAX_EXPANDED_BYTES, max_bytes * 100
            ):
                raise WorkflowError("XLSX expanded content exceeds limit")
            for item in entries:
                path_value = PurePosixPath(item.filename)
                if (
                    item.flag_bits & 1
                    or "\\" in item.filename
                    or path_value.is_absolute()
                    or any(part in (".", "..") for part in item.filename.split("/"))
                    or "\x00" in item.filename
                ):
                    raise WorkflowError("unsafe XLSX package entry")
            if package.testzip() is not None:
                raise WorkflowError("XLSX package checksum mismatch")
            content_types = _xml(package, "[Content_Types].xml")
            relationships = _xml(package, "_rels/.rels")
            workbook = _xml(package, "xl/workbook.xml")
            if (
                content_types.tag != CONTENT_TYPES + "Types"
                or workbook.tag != WORKBOOK
                or relationships.tag != RELATIONSHIPS + "Relationships"
            ):
                raise WorkflowError("invalid XLSX structural XML")
            office = [
                item
                for item in relationships
                if item.tag == RELATIONSHIPS + "Relationship"
                and item.get("Type") == OFFICE_DOCUMENT
            ]
            if (
                len(office) != 1
                or office[0].get("Target")
                not in ("xl/workbook.xml", "/xl/workbook.xml")
                or office[0].get("TargetMode", "Internal") != "Internal"
            ):
                raise WorkflowError("XLSX workbook relationship is invalid")
            overrides = [
                item
                for item in content_types
                if item.tag == CONTENT_TYPES + "Override"
                and item.get("PartName") == "/xl/workbook.xml"
            ]
            if len(overrides) != 1 or overrides[0].get("ContentType") != XLSX_MAIN:
                raise WorkflowError("XLSX workbook content type is invalid")
    except (
        OSError,
        EOFError,
        OverflowError,
        KeyError,
        ValueError,
        RuntimeError,
        NotImplementedError,
        zlib.error,
        zipfile.BadZipFile,
        ElementTree.ParseError,
        DefusedXmlException,
    ) as exc:
        raise WorkflowError("invalid XLSX package") from exc
