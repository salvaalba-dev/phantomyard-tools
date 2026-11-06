"""Synthetic XLSX structure checks; no spreadsheet formulas are executed."""

import struct
import zipfile

import pytest

from phantomdocs.workflow_processing import validate_input
from phantomdocs.workflows import WorkflowError

MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
TYPES = b"""<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>"""
WORKBOOK = (
    b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'
)
RELS = b"""<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""


def package(path, *, types=TYPES, workbook=WORKBOOK, extra=()):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", types)
        archive.writestr("_rels/.rels", RELS)
        archive.writestr("xl/workbook.xml", workbook)
        for name, data in extra:
            archive.writestr(name, data)


def check(path, maximum=1024 * 1024):
    return validate_input(
        path, MIME, {"media_types": [MIME]}, {"max_input_bytes": maximum}
    )


def test_valid_xlsx_package_is_measured_without_executing_contents(tmp_path):
    path = tmp_path / "sample.xlsx"
    package(path, extra=[("xl/worksheets/sheet1.xml", b"<c><f>1+1</f></c>")])
    result = check(path)
    assert result["size"] == path.stat().st_size
    assert result["media_type"] == MIME
    assert len(result["sha256"]) == 64


@pytest.mark.parametrize("case", ["nonzip", "wrong_type", "wrong_root", "path", "dtd"])
def test_invalid_packages_are_rejected(tmp_path, case):
    path = tmp_path / "sample.xlsx"
    if case == "nonzip":
        path.write_bytes(b"not a workbook")
    elif case == "wrong_type":
        package(
            path,
            types=TYPES.replace(
                b"spreadsheetml.sheet.main", b"spreadsheetml.template.main"
            ),
        )
    elif case == "wrong_root":
        package(path, workbook=b"<not-workbook/>")
    elif case == "path":
        package(path, extra=[("../outside", b"x")])
    else:
        package(
            path,
            workbook=b'<!DOCTYPE workbook [<!ENTITY x "x">]><workbook>&x;</workbook>',
        )
    with pytest.raises(WorkflowError):
        check(path)


def test_rejects_oversized_and_expansion_bomb(tmp_path):
    path = tmp_path / "sample.xlsx"
    package(path, extra=[("xl/large", b"x" * 200_000)])
    with pytest.raises(WorkflowError):
        check(path, maximum=1000)
    with pytest.raises(WorkflowError):
        check(path, maximum=10)


def test_duplicate_parts_are_rejected(tmp_path):
    path = tmp_path / "duplicate.xlsx"
    with pytest.warns(UserWarning, match="Duplicate name"):
        package(path, extra=[("xl/workbook.xml", WORKBOOK)])
    with pytest.raises(WorkflowError):
        check(path)


def test_incomplete_or_corrupted_zip_is_rejected(tmp_path):
    path = tmp_path / "incomplete.xlsx"
    package(path)
    data = path.read_bytes()
    path.write_bytes(data[:-12])
    with pytest.raises(WorkflowError):
        check(path)


@pytest.mark.parametrize(
    "field,value", [("count", 3000), ("directory_size", 10_000_000)]
)
def test_directory_limits_are_checked_before_opening_zip(
    tmp_path, field, value, monkeypatch
):
    path = tmp_path / "oversized.xlsx"
    package(path)
    data = bytearray(path.read_bytes())
    end = data.rfind(b"PK\x05\x06")
    if field == "count":
        struct.pack_into("<HH", data, end + 8, value, value)
    else:
        struct.pack_into("<I", data, end + 12, value)
    path.write_bytes(data)

    def fail_if_opened(*args, **kwargs):
        pytest.fail("ZipFile must not load an oversized central directory")

    monkeypatch.setattr("phantomdocs.workflow_xlsx.zipfile.ZipFile", fail_if_opened)
    with pytest.raises(WorkflowError):
        check(path)
