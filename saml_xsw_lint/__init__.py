"""saml-xsw-lint - offline SAML response and XML-signature trust analyser.

This package makes no network requests of any kind. There is no metadata fetch,
no key fetch and no revocation check, and ``tests/test_no_network.py`` asserts
that no module here imports a networking library.

It is not a signature verifier. See the README section "What this tool is not".
"""

from .engine import analyse
from .findings import CATALOGUE, Finding, Severity
from .model import Document

__version__ = "0.1.0"
__all__ = ["analyse", "CATALOGUE", "Document", "Finding", "Severity", "__version__"]
