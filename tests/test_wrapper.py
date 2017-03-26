import pytest
from certmaestro.wrapper import Name
import asn1crypto.x509 as asn1x509


class TestName:
    def test_name_from_str(self):
        long_name = ('/C=HU/ST=Pest megye/L=Budapest/O=Certmaestro/OU=Single/CN=vpn.example.com'
                     '/name=EasyRSA/emailAddress=somebody@somewhere.com')
        name = Name(long_name)
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

    def test_name_from_asn1(self):
        asn1name = asn1x509.Name.build({
            'country_name': 'HU',
            'state_or_province_name': 'Pest megye',
            'locality_name': 'Budapest',
            'organization_name': 'Certmaestro',
            'common_name': 'vpn.example3.com'
        })
        name = Name.from_asn1(asn1name)
        assert name.common_name == 'vpn.example3.com'

    def test_names_are_comparable(self):
        assert Name('/C=HU/L=Budapest/O=asf') == Name('/C=HU/L=Budapest/O=asf')

    def test_names_are_equal_with_different_order(self):
        assert Name('/C=HU/L=Budapest/O=asf') == Name('/O=asf/C=HU/L=Budapest')
