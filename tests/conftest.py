"""Shared pytest fixtures."""

import pytest
from pykeepass import create_database


@pytest.fixture(scope="session")
def kdbx_db(tmp_path_factory):
    """Build one real KDBX database with a known password, reused across tests.

    Created once per session (the file is never modified by tests) so the cost of
    key derivation is paid a single time.
    """
    path = tmp_path_factory.mktemp("db") / "test.kdbx"
    password = "Sunflower42!"
    kp = create_database(str(path), password=password)
    kp.save()
    return str(path), password
