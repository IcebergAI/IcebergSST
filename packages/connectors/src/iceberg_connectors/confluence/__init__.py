"""The Confluence connector (#10 — Cloud REST v2 first).

Split three ways because the three fail differently and are worth reading apart:

* :mod:`~iceberg_connectors.confluence.client` — cursors, credentials, and a server
  asking to be left alone.
* :mod:`~iceberg_connectors.confluence.storage` — storage-format XHTML flattened to
  the text detection actually reads.
* :mod:`~iceberg_connectors.confluence.connector` — spaces, pages, comments,
  attachments, and the locators that make a finding's identity survive a re-scan.

Cloud is the target flavor; the seam that would differ for Server/Data Center is
authentication, and it is one field in the connection blob (see the client's module
docstring), not a shape the ``Connector`` protocol has to know about.
"""

from iceberg_connectors.confluence.client import (
    ConfluenceClient,
    Credential,
    DownloadTooLarge,
    RateLimited,
    RateLimitPolicy,
)
from iceberg_connectors.confluence.connector import (
    CONFLUENCE_CONNECTOR_TYPE,
    ConfluenceConnector,
)
from iceberg_connectors.confluence.storage import body_text, storage_to_text

__all__ = [
    "CONFLUENCE_CONNECTOR_TYPE",
    "ConfluenceClient",
    "ConfluenceConnector",
    "Credential",
    "DownloadTooLarge",
    "RateLimitPolicy",
    "RateLimited",
    "body_text",
    "storage_to_text",
]
