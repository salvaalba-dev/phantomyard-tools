"""Read-only metadata inventory of one explicitly selected Drive folder."""

from __future__ import annotations

import json
import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import click

from .workflow_drive_reader import _NoRedirect
from .workflows import WorkflowError, reference_is_safe

MAX_ITEMS = 1000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_PAGES = 100
_FOLDER_MIME = "application/vnd.google-apps.folder"
_LIST_FIELDS = (
    "nextPageToken,incompleteSearch,files("
    "id,name,mimeType,parents,size,version,md5Checksum,trashed)"
)


class DriveInboxInventory:
    """List direct metadata children of one configured Drive inbox folder.

    This class never reads file bodies or writes to Drive. A complete inventory
    means all API pages for this query were received; it is not a transactional
    snapshot and must be rechecked before any later operation.
    """

    def __init__(
        self, token_file, *, max_items=MAX_ITEMS, page_size=200, transport=None
    ):
        if (
            type(max_items) is not int
            or not 1 <= max_items <= MAX_ITEMS
            or type(page_size) is not int
            or not 1 <= page_size <= 1000
        ):
            raise WorkflowError("invalid Drive inventory bounds")
        path = Path(token_file)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise WorkflowError("Drive token must be in a private regular file")
        if os.name == "posix" and (
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise WorkflowError(
                "Drive token file must be owned by caller with mode 0600"
            )
        token = path.read_text(encoding="utf-8").strip()
        if not token or len(token) > 16384 or any(ord(c) < 33 for c in token):
            raise WorkflowError("invalid Drive access-token file")
        self.token = token
        self.max_items = max_items
        self.page_size = page_size
        self.transport = transport or urllib.request.build_opener(_NoRedirect()).open

    def _get_json(self, url):
        request = urllib.request.Request(
            url,
            headers={"Authorization": "Bearer " + self.token},
            method="GET",
        )
        try:
            with self.transport(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise WorkflowError("cannot read Drive inbox metadata") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise WorkflowError("oversized Drive metadata response")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkflowError("invalid Drive metadata response") from exc
        if not isinstance(value, dict):
            raise WorkflowError("invalid Drive metadata response")
        return value, len(raw)

    def _file_url(self, file_id, fields):
        return (
            "https://www.googleapis.com/drive/v3/files/"
            + urllib.parse.quote(file_id, safe="")
            + "?"
            + urllib.parse.urlencode({"fields": fields, "supportsAllDrives": "true"})
        )

    @staticmethod
    def _provider_string(value, *, field, max_length):
        if type(value) is int and 0 <= value < 10**max_length:
            return str(value)
        if isinstance(value, str) and re.fullmatch(rf"[0-9]{{1,{max_length}}}", value):
            return value
        raise WorkflowError("invalid Drive " + field + " metadata")

    def _item(self, raw, inbox_id, seen):
        required = {"id", "name", "mimeType", "parents"}
        allowed = required | {"size", "version", "md5Checksum", "trashed"}
        if not isinstance(raw, dict) or not required <= set(raw) or set(raw) - allowed:
            raise WorkflowError("invalid Drive inbox item metadata")
        file_id = raw["id"]
        if (
            not isinstance(file_id, str)
            or len(file_id) > 200
            or not reference_is_safe("gdrive://" + file_id)
            or file_id in seen
        ):
            raise WorkflowError("invalid or duplicate Drive inbox item identity")
        seen.add(file_id)
        if (
            not isinstance(raw["name"], str)
            or not 0 < len(raw["name"]) <= 512
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in raw["name"]
            )
            or not isinstance(raw["mimeType"], str)
            or not re.fullmatch(r"[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+", raw["mimeType"])
            or not isinstance(raw["parents"], list)
            or not 0 < len(raw["parents"]) <= 10
            or not all(isinstance(parent, str) for parent in raw["parents"])
            or len(set(raw["parents"])) != len(raw["parents"])
            or inbox_id not in raw["parents"]
            or "trashed" in raw
            and type(raw["trashed"]) is not bool
        ):
            raise WorkflowError("invalid Drive inbox item metadata")
        item = {
            "id": file_id,
            "name": raw["name"],
            "mimeType": raw["mimeType"],
            "parents": raw["parents"],
        }
        if "trashed" in raw:
            item["trashed"] = raw["trashed"]
        for field, max_length in (("size", 20), ("version", 40)):
            if field in raw:
                item[field] = self._provider_string(
                    raw[field], field=field, max_length=max_length
                )
        if "md5Checksum" in raw:
            checksum = raw["md5Checksum"]
            if not isinstance(checksum, str) or not re.fullmatch(
                r"[0-9a-fA-F]{32}", checksum
            ):
                raise WorkflowError("invalid Drive checksum metadata")
            item["md5Checksum"] = checksum.lower()
        return item

    def inventory(self, inbox_ref):
        if not isinstance(inbox_ref, str) or not reference_is_safe(inbox_ref):
            raise WorkflowError(
                "Drive inventory requires one exact safe folder reference"
            )
        inbox_id = inbox_ref.split("://", 1)[1]
        folder, total_bytes = self._get_json(
            self._file_url(inbox_id, "id,mimeType,driveId,trashed")
        )
        if (
            folder.get("id") != inbox_id
            or folder.get("mimeType") != _FOLDER_MIME
            or folder.get("trashed", False) is not False
        ):
            raise WorkflowError("selected Drive inbox is not an active folder")
        drive_id = folder.get("driveId")
        if drive_id is not None and (
            not isinstance(drive_id, str)
            or not reference_is_safe("gdrive://" + drive_id)
        ):
            raise WorkflowError("invalid Drive shared-drive identity")

        parameters = {
            "corpora": "drive" if drive_id else "user",
            "q": "'" + inbox_id + "' in parents",
            "fields": _LIST_FIELDS,
            "includeItemsFromAllDrives": "true",
            "supportsAllDrives": "true",
            "pageSize": str(self.page_size),
            "spaces": "drive",
        }
        if drive_id:
            parameters["driveId"] = drive_id
        items, seen_ids, seen_tokens = [], set(), set()
        page_token = None
        pages = 0
        while True:
            pages += 1
            if pages > MAX_PAGES:
                raise WorkflowError("Drive inbox listing exceeds the page limit")
            query = dict(parameters)
            if page_token:
                query["pageToken"] = page_token
            page, page_bytes = self._get_json(
                "https://www.googleapis.com/drive/v3/files?"
                + urllib.parse.urlencode(query)
            )
            total_bytes += page_bytes
            if total_bytes > MAX_TOTAL_RESPONSE_BYTES:
                raise WorkflowError("Drive inbox metadata exceeds the total byte limit")
            incomplete = page.get("incompleteSearch", False)
            if type(incomplete) is not bool or incomplete:
                raise WorkflowError("Drive inbox listing is incomplete")
            rows = page.get("files")
            if not isinstance(rows, list):
                raise WorkflowError("invalid Drive inbox listing")
            for row in rows:
                if len(items) >= self.max_items:
                    raise WorkflowError("Drive inbox exceeds the configured item limit")
                items.append(self._item(row, inbox_id, seen_ids))
            next_token = page.get("nextPageToken")
            if next_token is None:
                break
            if (
                not isinstance(next_token, str)
                or not next_token
                or len(next_token) > 8192
                or next_token in seen_tokens
            ):
                raise WorkflowError("invalid or repeated Drive page token")
            seen_tokens.add(next_token)
            page_token = next_token
        result = {"version": 1, "complete": True, "items": items}
        encoded = json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise WorkflowError("Drive inbox inventory exceeds the 4 MiB output limit")
        return result


@click.command("inbox-inventory")
@click.option("--inbox-ref", required=True)
@click.option(
    "--drive-token-file", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option(
    "--max-items", type=click.IntRange(min=1, max=MAX_ITEMS), default=MAX_ITEMS
)
def inventory_command(inbox_ref, drive_token_file, max_items):
    """List complete metadata for one declared Drive inbox; never read file bodies."""
    try:
        result = DriveInboxInventory(drive_token_file, max_items=max_items).inventory(
            inbox_ref
        )
    except WorkflowError as error:
        raise click.ClickException(str(error)) from error
    except (OSError, ValueError, TypeError) as error:
        raise click.ClickException("cannot load Drive inbox inventory") from error
    click.echo(json.dumps(result, indent=2, ensure_ascii=False))
