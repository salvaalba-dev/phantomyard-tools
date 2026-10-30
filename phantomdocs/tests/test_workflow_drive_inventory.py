"""Google Drive inbox enumeration is bounded, metadata-only and fail-closed."""

from __future__ import annotations

import io
import json
import os
import urllib.error
import urllib.parse

import pytest
from click.testing import CliRunner

from phantomdocs.cli import main
from phantomdocs.workflow_drive_inventory import DriveInboxInventory
from phantomdocs.workflow_scan import _inventory
from phantomdocs.workflows import WorkflowError


def file_row(file_id="file-1", *, parents=None, **updates):
    result = {
        "id": file_id,
        "name": "Application.xlsx",
        "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "parents": parents or ["inbox-id"],
        "size": "773",
        "version": "29",
        "md5Checksum": "a" * 32,
        "trashed": False,
    }
    result.update(updates)
    return result


def make_inventory(
    tmp_path, pages, *, drive_id=None, folder_id="inbox-id", transport_error=None
):
    token_file = tmp_path / "test-token"
    token_file.write_text("synthetic-test-token", encoding="utf-8")
    token_file.chmod(0o600)
    requests = []
    pages = list(pages)

    def transport(request, timeout):
        requests.append(request)
        if transport_error:
            raise transport_error(request, timeout)
        parsed = urllib.parse.urlsplit(request.full_url)
        if parsed.path == f"/drive/v3/files/{folder_id}":
            value = {
                "id": folder_id,
                "mimeType": "application/vnd.google-apps.folder",
                "trashed": False,
            }
            if drive_id:
                value["driveId"] = drive_id
        elif parsed.path == "/drive/v3/files":
            index = (
                len(
                    [
                        r
                        for r in requests
                        if urllib.parse.urlsplit(r.full_url).path == parsed.path
                    ]
                )
                - 1
            )
            value = pages[min(index, len(pages) - 1)]
        else:
            raise AssertionError("unexpected Drive endpoint")
        return io.BytesIO(json.dumps(value).encode("utf-8"))

    inventory = DriveInboxInventory(token_file, transport=transport)
    return inventory, requests


def test_lists_all_pages_and_emits_scanner_inventory(tmp_path):
    pages = [
        {
            "incompleteSearch": False,
            "files": [file_row(size=773, version=29)],
            "nextPageToken": "page-two",
        },
        {
            "incompleteSearch": False,
            "files": [file_row("file-2", name="Notes.txt", size="0", trashed=True)],
        },
    ]
    reader, requests = make_inventory(tmp_path, pages)

    result = reader.inventory("gdrive://inbox-id")
    _inventory(result)

    assert result == {
        "version": 1,
        "complete": True,
        "items": [
            {
                "id": "file-1",
                "name": "Application.xlsx",
                "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "parents": ["inbox-id"],
                "size": "773",
                "version": "29",
                "md5Checksum": "a" * 32,
                "trashed": False,
            },
            {
                "id": "file-2",
                "name": "Notes.txt",
                "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "parents": ["inbox-id"],
                "size": "0",
                "version": "29",
                "md5Checksum": "a" * 32,
                "trashed": True,
            },
        ],
    }
    assert len(requests) == 3
    assert all(request.get_method() == "GET" for request in requests)
    assert all(
        request.full_url.startswith("https://www.googleapis.com/drive/v3/files")
        for request in requests
    )
    assert all(
        request.get_header("Authorization") == "Bearer synthetic-test-token"
        for request in requests
    )
    first_page = urllib.parse.parse_qs(
        urllib.parse.urlsplit(requests[1].full_url).query
    )
    second_page = urllib.parse.parse_qs(
        urllib.parse.urlsplit(requests[2].full_url).query
    )
    assert first_page["corpora"] == ["user"]
    assert first_page["q"] == ["'inbox-id' in parents"]
    assert first_page["includeItemsFromAllDrives"] == ["true"]
    assert second_page["pageToken"] == ["page-two"]


def test_shared_drive_folder_uses_its_drive_corpus(tmp_path):
    reader, requests = make_inventory(
        tmp_path,
        [{"incompleteSearch": False, "files": []}],
        drive_id="shared-drive-id",
    )

    assert reader.inventory("gdrive://inbox-id")["items"] == []
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(requests[1].full_url).query)
    assert query["corpora"] == ["drive"]
    assert query["driveId"] == ["shared-drive-id"]


@pytest.mark.parametrize(
    "page",
    [
        {"incompleteSearch": True, "files": []},
        {"incompleteSearch": "false", "files": []},
        {"incompleteSearch": False},
        {"incompleteSearch": False, "files": "not-a-list"},
    ],
)
def test_incomplete_or_malformed_list_results_are_refused(tmp_path, page):
    reader, _ = make_inventory(tmp_path, [page])
    with pytest.raises(WorkflowError):
        reader.inventory("gdrive://inbox-id")


def test_default_false_metadata_fields_may_be_omitted(tmp_path):
    item = file_row()
    item.pop("trashed")
    reader, _ = make_inventory(
        tmp_path,
        [{"files": [item]}],
    )
    result = reader.inventory("gdrive://inbox-id")
    assert result["complete"] is True
    assert "trashed" not in result["items"][0]


def test_metadata_values_outside_scan_contract_are_refused(tmp_path):
    reader, _ = make_inventory(
        tmp_path,
        [{"incompleteSearch": False, "files": [file_row(size="9" * 21)]}],
    )
    with pytest.raises(WorkflowError, match="size metadata"):
        reader.inventory("gdrive://inbox-id")


def test_repeated_page_token_is_refused(tmp_path):
    reader, _ = make_inventory(
        tmp_path,
        [
            {"incompleteSearch": False, "files": [], "nextPageToken": "repeat"},
            {"incompleteSearch": False, "files": [], "nextPageToken": "repeat"},
        ],
    )
    with pytest.raises(WorkflowError, match="repeated"):
        reader.inventory("gdrive://inbox-id")


def test_file_outside_selected_parent_is_refused(tmp_path):
    reader, _ = make_inventory(
        tmp_path,
        [{"incompleteSearch": False, "files": [file_row(parents=["other"])]}],
    )
    with pytest.raises(WorkflowError, match="metadata"):
        reader.inventory("gdrive://inbox-id")


def test_duplicate_identity_across_pages_is_refused(tmp_path):
    reader, _ = make_inventory(
        tmp_path,
        [
            {
                "incompleteSearch": False,
                "files": [file_row()],
                "nextPageToken": "next",
            },
            {"incompleteSearch": False, "files": [file_row()]},
        ],
    )
    with pytest.raises(WorkflowError, match="duplicate"):
        reader.inventory("gdrive://inbox-id")


def test_item_limit_and_shared_drive_id_are_enforced(tmp_path):
    reader, _ = make_inventory(
        tmp_path,
        [{"incompleteSearch": False, "files": [file_row(), file_row("file-2")]}],
    )
    reader.max_items = 1
    with pytest.raises(WorkflowError, match="item limit"):
        reader.inventory("gdrive://inbox-id")
    with pytest.raises(WorkflowError, match="shared-drive"):
        make_inventory(
            tmp_path,
            [{"incompleteSearch": False, "files": []}],
            drive_id="unsafe/id",
        )[0].inventory("gdrive://inbox-id")


@pytest.mark.parametrize(
    "folder,ref",
    [
        (
            {
                "id": "other",
                "mimeType": "application/vnd.google-apps.folder",
                "trashed": False,
            },
            "gdrive://inbox-id",
        ),
        (
            {"id": "inbox-id", "mimeType": "application/pdf", "trashed": False},
            "gdrive://inbox-id",
        ),
        (
            {
                "id": "inbox-id",
                "mimeType": "application/vnd.google-apps.folder",
                "trashed": True,
            },
            "gdrive://inbox-id",
        ),
        (
            {
                "id": "inbox-id",
                "mimeType": "application/vnd.google-apps.folder",
                "trashed": False,
            },
            "gdrive://bad?id",
        ),
    ],
)
def test_invalid_folder_or_reference_is_refused(tmp_path, folder, ref):
    reader, requests = make_inventory(
        tmp_path, [{"incompleteSearch": False, "files": []}]
    )
    original = reader._get_json
    reader._get_json = lambda url: (
        (folder, 10) if "/inbox-id?" in url else original(url)
    )
    with pytest.raises(WorkflowError):
        reader.inventory(ref)
    if ref != "gdrive://inbox-id":
        assert len(requests) == 0


def test_invalid_api_response_and_http_failure_hide_token(tmp_path):
    reader, _ = make_inventory(tmp_path, [])
    reader.transport = lambda request, timeout: io.BytesIO(b"not-json")
    with pytest.raises(WorkflowError, match="invalid Drive metadata"):
        reader.inventory("gdrive://inbox-id")

    def denied(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "denied", {}, None)

    reader.transport = denied
    with pytest.raises(WorkflowError) as error:
        reader.inventory("gdrive://inbox-id")
    assert "synthetic-test-token" not in str(error.value)


def test_command_emits_json_inventory(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-test-token", encoding="utf-8")
    token.chmod(0o600)

    # The CLI uses the real transport, so replace only the adapter constructor.
    from phantomdocs import workflow_drive_inventory

    class FakeInventory:
        def __init__(self, token_file, *, max_items):
            assert token_file == str(token)
            assert max_items == 17

        def inventory(self, inbox_ref):
            return {"version": 1, "complete": True, "items": []}

    old = workflow_drive_inventory.DriveInboxInventory
    workflow_drive_inventory.DriveInboxInventory = FakeInventory
    try:
        result = CliRunner().invoke(
            main,
            [
                "workflow",
                "inbox-inventory",
                "--inbox-ref",
                "gdrive://inbox-id",
                "--drive-token-file",
                str(token),
                "--max-items",
                "17",
            ],
        )
    finally:
        workflow_drive_inventory.DriveInboxInventory = old
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "version": 1,
        "complete": True,
        "items": [],
    }


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode check")
def test_public_token_file_is_refused(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-test-token", encoding="utf-8")
    token.chmod(0o644)
    with pytest.raises(WorkflowError, match="0600"):
        DriveInboxInventory(token)
