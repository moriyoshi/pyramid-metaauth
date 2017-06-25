import warnings


def test_it():
    from ..utils import combine_headers
    with warnings.catch_warnings(record=True) as warns:
        result = combine_headers(
            [
                ('Set-Cookie', 'b=1'),
                ('FoO', 'a'),
                ],
            [
                ('WWW-Authenticate', 'Basic; realm="foo"'),
                ('set-cookie', 'a=1; Path=/; Domain=example.com'),
                ('foo', 'b'),
                ],
            )
    assert len(warns) == 0
    assert len(result) == 5
    assert result[0] == ('Set-Cookie', 'b=1')
    assert result[1] == ('Set-Cookie', 'a=1; Path=/; Domain=example.com')
    assert result[2] == ('FoO', 'a')
    assert result[3] == ('FoO', 'b')
    assert result[4] == ('WWW-Authenticate', 'Basic; realm="foo"')


def test_warn_allowed():
    from ..utils import combine_headers
    with warnings.catch_warnings(record=True) as warns:
        result = combine_headers(
            [
                ('WWW-Authenticate', 'Basic; realm="foo"'),
                ],
            [
                ('WWW-Authenticate', 'Basic; realm="bar"'),
                ],
            )
    assert len(warns) == 1
    assert len(result) == 1
    assert result[0] == ('WWW-Authenticate', 'Basic; realm="foo"')


def test_warn_unalloweds():
    from ..utils import combine_headers
    with warnings.catch_warnings(record=True) as warns:
        result = combine_headers(
            [
                ('Content-Type', 'text/plain'),
                ],
            []
            )
    assert len(warns) == 1
    assert len(result) == 1


def test_warn_unallowed_multiple_times():
    from ..utils import combine_headers
    with warnings.catch_warnings(record=True) as warns:
        result = combine_headers(
            [
                ('Content-Type', 'text/foo'),
                ],
            [
                ('content-Type', 'text/bar'),
                ('Content-type', 'text/baz'),
                ],
            )
    assert len(warns) >= 2
    assert len(result) == 1
    assert result[0] == ('Content-Type', 'text/foo')
