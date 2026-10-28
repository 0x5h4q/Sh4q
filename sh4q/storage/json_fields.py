from __future__ import annotations

import json
from typing import Any

from .errors import CorruptRecordError


#: Returned when a caller asked to collect malformed rows and no fallback was
#: supplied. A stored JSON `null` is a real value, so a plain `None` cannot
#: stand in for "the decode failed".
MALFORMED = object()


def decode_json(
    raw: str | bytes | None,
    *,
    field: str,
    record_id: str | None = None,
    skipped: list[CorruptRecordError] | None = None,
    fallback: Any = MALFORMED,
) -> Any:
    """Decode one stored JSON field.

    With no `skipped` collector the failure raises `CorruptRecordError`, which
    names the field and the row. When a collector is supplied the error is
    appended to it and `fallback` is returned, letting a listing skip the row
    and report a count instead of aborting the whole view.

    `record_id` is optional because some callers only have a value tuple. Pass
    it whenever the row has an id; it is the part an operator can search for.
    """
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as error:
        issue = CorruptRecordError(
            field=field,
            record_id=record_id,
            detail=str(error),
        )
        if skipped is None:
            raise issue from error
        skipped.append(issue)
        return fallback


def decode_object(
    raw: str | bytes | None,
    *,
    field: str,
    record_id: str | None = None,
    skipped: list[CorruptRecordError] | None = None,
    fallback: Any = MALFORMED,
) -> Any:
    """Decode a stored JSON object, rejecting other JSON values.

    Attributes, evidence content, and event payloads are mappings by contract.
    A valid JSON array or scalar would decode but then fail on `.get`, so it is
    treated as the same kind of corruption and reported the same way.
    """
    value = decode_json(
        raw,
        field=field,
        record_id=record_id,
        skipped=skipped,
        fallback=fallback,
    )
    if value is fallback and skipped is not None:
        return fallback
    if isinstance(value, dict):
        return value
    issue = CorruptRecordError(
        field=field,
        record_id=record_id,
        detail=f"expected an object, got {type(value).__name__}",
    )
    if skipped is None:
        raise issue
    skipped.append(issue)
    return fallback
