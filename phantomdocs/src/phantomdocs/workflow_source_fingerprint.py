"""Deterministic identity for a metadata-only reference-document scan."""

from .workflows import digest


def reference_scan_id(organization, ref, metadata):
    """Bind a proposal to its observed source without asserting authenticity."""
    return "reference-" + digest(
        {
            "organization": organization,
            "ref": ref,
            "fingerprint": {
                key: metadata[key]
                for key in ("size", "version", "md5Checksum", "mimeType")
            },
        }
    )
