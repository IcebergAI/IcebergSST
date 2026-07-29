import iceberg_api


def test_version() -> None:
    assert isinstance(iceberg_api.__version__, str)
