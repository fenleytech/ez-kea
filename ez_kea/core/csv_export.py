# SPDX-FileCopyrightText: 2026 Kaleb Fenley
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

"""
ez_kea/core/csv_export.py

The streaming-CSV-response scaffold shared by the Leases/Reservations export
endpoints (routes/dhcp4.py, routes/dhcp6.py) -- buffer/flush a csv.writer in
bounded chunks, cap the row count with an explicit truncation marker rather
than ending an export silently short, and set the download filename/headers.
Pulled out once four call sites needed the exact same shape (see
routes/system.py's logs_export() for the pattern this was lifted from).
"""
import csv
import io
from datetime import datetime
from typing import Any, Callable, Iterable, List, Sequence

from flask import Response, current_app, stream_with_context


def stream_csv_response(
    header: Sequence[str],
    rows: Iterable[Any],
    row_to_values: Callable[[Any], List[Any]],
    filename_prefix: str,
    max_rows: int,
) -> Response:
    """Stream `rows` as a CSV attachment, flushing every 500 rows so a large
    export costs bounded memory instead of materialising everything first."""

    def generate():
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        def flush() -> str:
            chunk = buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
            return chunk

        writer.writerow(header)
        yield flush()

        written = 0
        for row in rows:
            if written >= max_rows:
                writer.writerow([
                    f"# TRUNCATED at {max_rows} rows - narrow the filters and export again"
                ])
                yield flush()
                break
            writer.writerow(row_to_values(row))
            written += 1
            if written % 500 == 0:
                yield flush()
        yield flush()

    filename = f"{filename_prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return current_app.response_class(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
