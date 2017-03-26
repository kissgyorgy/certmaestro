import pytest
from pathlib import Path
from certmaestro.backends.openssl.parser import OpenSSLDbParser
from certmaestro.wrapper import Name


@pytest.fixture(scope='session')
def data_dir():
    return Path(__file__).parent / 'data'


@pytest.fixture(scope='session')
def empty_file(data_dir):
    return data_dir / 'empty.txt'


class TestDatabaseParser:
    def test_empty_database_is_fine(self, empty_file):
        OpenSSLDbParser(empty_file)

    def test_iterating_over_empty_file_gives_no_error(self, empty_file):
        for entry in OpenSSLDbParser(empty_file):
            pass

    def test_get_by_serial_number_on_empty_file(self, empty_file):
        db = OpenSSLDbParser(empty_file)
        assert db.get_by_serial_number('01') is None

    def test_get_by_serial_on_single_entry(self, data_dir):
        db = OpenSSLDbParser(data_dir / 'one_valid.txt')
        assert db.get_by_serial_number('01').name == Name('/C=HU/L=Budapest/O=asf')
