import iceberg_engine


def test_version() -> None:
    assert isinstance(iceberg_engine.__version__, str)
