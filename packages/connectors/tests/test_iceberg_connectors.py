import iceberg_connectors


def test_version() -> None:
    assert isinstance(iceberg_connectors.__version__, str)
