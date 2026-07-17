"""Target intelligence (spec §15 ``targets/``).

``immunefi_client`` fetches + parses Immunefi program data (the Next.js app-router
RSC flight stream) and ranks the board; ``source_resolver`` clones the in-scope
source repos and maps in-scope contract names → source files. Both feed S0 Discovery.
"""

from __future__ import annotations
