"""Background workers.

The scan worker is a plain database-backed loop; there is no broker and no
distributed queue.
"""

from app.workers.scan_worker import ScanWorker, main

__all__ = ["ScanWorker", "main"]
