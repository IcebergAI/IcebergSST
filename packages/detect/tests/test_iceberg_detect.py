import iceberg_detect


def test_version() -> None:
    assert isinstance(iceberg_detect.__version__, str)
