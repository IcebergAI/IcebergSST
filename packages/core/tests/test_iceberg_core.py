import iceberg_core


def test_version() -> None:
    assert isinstance(iceberg_core.__version__, str)
