import datetime as dt
import asn1crypto.core as asn1core
from asn1crypto.crl import RevokedCertificate


rc = RevokedCertificate({'user_certificate': 1,
                         'revocation_date': asn1core.UTCTime(dt.datetime.utcnow())})
