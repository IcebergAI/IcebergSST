"""The SMB/NFS file-share connector (#145)."""

from iceberg_connectors.fileshare.connector import (
    FILESHARE_CONNECTOR_TYPE,
    FileshareConnector,
)

__all__ = ["FILESHARE_CONNECTOR_TYPE", "FileshareConnector"]
