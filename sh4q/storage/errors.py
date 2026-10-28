from __future__ import annotations


class StorageError(Exception):
    """A database operation failed in a way the operator can act on.

    The path and operation are attributes rather than only words in the
    message so a caller can distinguish "this database is locked" from "this
    record is corrupt" without parsing.
    """

    def __init__(
        self,
        message: str,
        *,
        database: str | None = None,
        operation: str = "database operation",
    ) -> None:
        self.database = database
        self.operation = operation
        super().__init__(message)


class CorruptRecordError(StorageError):
    """A stored JSON field could not be decoded.

    Sh4q writes these fields itself; a value that does not parse means the row
    was truncated, edited by hand, or written by a different schema. The row
    id (when known) lets an operator find it without guessing.
    """

    def __init__(
        self,
        *,
        field: str,
        record_id: str | None = None,
        detail: str = "",
    ) -> None:
        self.field = field
        self.record_id = str(record_id) if record_id is not None else None
        self.detail = detail
        location = f"record {record_id}" if record_id else "a stored record"
        super().__init__(
            f"{location} has invalid JSON in {field}: {detail}",
            operation="decode stored JSON",
        )
