from certmaestro.wrapper import hexify


class Testhexify:
    def test_small_integer(self):
        assert hexify(1) == '01'

    def test_zero(self):
        assert hexify(0) == '00'

    def test_even_length(self):
        assert hexify(17) == '11'

    def test_contains_letter(self):
        assert hexify(9999) == '27:0f'

    def test_long_integer(self):
        long_int = 62875419084137315581790470316441984428164377498
        expected = '0b:03:6e:69:d8:f3:ac:3c:d4:b0:6f:16:31:50:85:68:5c:2d:eb:9a'
        assert hexify(long_int) == expected
