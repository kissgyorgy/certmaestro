import pytest
from certmaestro.wrapper import Name


class TestName:
    def test_name_from_str(self):
        long_name = ('/C=HU/ST=Pest megye/L=Budapest/O=Certmaestro/OU=Single/CN=vpn.example.com'
                     '/name=EasyRSA/emailAddress=somebody@somewhere.com')
        name = Name.from_str(long_name)
        assert name.common_name == 'vpn.example.com'

    def test_name_from_dict(self):
        name = Name.from_dict({
            'country_name': 'HU',
            'state_or_province_name': 'Pest megye',
            'locality_name': 'Budapest',
            'organization_name': 'Certmaestro',
            'common_name': 'vpn.example2.com'
        })
        assert name.common_name == 'vpn.example2.com'
