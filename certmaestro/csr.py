import enum


class CsrPolicy(enum.Enum):
    FROMCA = 'FROMCA'
    REQUIRED = 'REQUIRED'
    OPTIONAL = 'OPTIONAL'


class CsrBuilder:

    def __init__(self, policy: dict, defaults: dict):
        self.policy = policy
        self._values = defaults

    def __getitem__(self, key):
        return self._values[key]

    @property
    def common_name(self):
        return self._values['common_name']

    def __setitem__(self, key, value):
        self._values[key] = value

    def _make_subject_piece(self, char, field):
        field_val = self._values.get(field)
        if field_val is not None and self.policy[field] == CsrPolicy.REQUIRED:
            return char + field_val
        return ''

    @property
    def subject(self):
        return ''.join((
            self._make_subject_piece('/CN=', 'common_name'),
            self._make_subject_piece('/C=', 'country'),
            self._make_subject_piece('/ST=', 'state'),
            self._make_subject_piece('/L=', 'locality'),
            self._make_subject_piece('/O=', 'org_name'),
            self._make_subject_piece('/OU=', 'org_unit'),
            self._make_subject_piece('/emailAddress=', 'email'),
        ))
