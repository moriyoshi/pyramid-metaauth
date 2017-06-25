from warnings import warn


unallowed_headers = {
    'accept-patch': 'Accept-Patch',
    'accept-ranges': 'Accept-Ranges',
    'access-control-allow-origin': 'Access-Control-Allow-Origin',
    'age': 'Age',
    'allow': 'Allow',
    'alt-svc': 'Alt-Svc',
    'cache-control': 'Cache-Control',
    'connection': 'Connection',
    'content-disposition': 'Content-Disposition',
    'content-encoding': 'Content-Encoding',
    'content-language': 'Content-Language',
    'content-length': 'Content-Length',
    'content-md5': 'Content-MD5',
    'content-range': 'Content-Range',
    'content-type': 'Content-Type',
    'date': 'Date',
    'etag': 'ETag',
    'expires': 'Expires',
    'last-modified': 'Last-Modified',
    'link': 'Link',
    'p3p': 'P3P',
    'pragma': 'Pragma',
    'proxy-authenticate': 'Proxy-Authenticate',
    'public-key-pins': 'Public-Key-Pins',
    'retry-after': 'Retry-After',
    'server': 'Server',
    'strict-transport-security': 'Strict-Transport-Security',
    'tk': 'Tk',
    'trailer': 'Trailer',
    'transfer-encoding': 'Transfer-Encoding',
    'upgrade': 'Upgrade',
    'vary': 'Vary',
    'via': 'Via',
    'warning': 'Warning',
    'x-frame-options': 'X-Frame-Options',
    }

allowed_singleton_headers = {
    'www-authenticate': 'WWW-Authenticate',
    'location': 'Location',
    'content-location': 'Content-Location',
    'refresh': 'Refresh',
    }


def combine_headers(headers, headers_to_add):
    headers += headers_to_add

    headers_indexes = {}
    for i, (hname, value) in enumerate(headers):
        k = hname.lower()
        _hname, indexes = headers_indexes.get(k) or (None, [])
        if k == 'set-cookie':
            canonical_hname = 'Set-Cookie'
        else:
            canonical_hname = unallowed_headers.get(k)
            if canonical_hname:
                warn('sending {0} from an authentication policy is unacceptable'.format(canonical_hname))
            else:
                canonical_hname = allowed_singleton_headers.get(k)
            if canonical_hname:
                if indexes:
                    warn('ignoring non-first occurrences of {0} headers as sending multiple ones is not permitted.  (value for ignored header: {1})'.format(canonical_hname, value))
                    canonical_hname = None
            else:
                canonical_hname = _hname or hname

        if canonical_hname is not None:
            indexes.append((i, value))
            headers_indexes[k] = (canonical_hname, indexes)

    result = []
    for k, values in sorted(headers_indexes.items(), key=lambda pair: pair[1][1][0][0]):
        hname = values[0] 
        for i, value in values[1]:
            result.append((hname, value))
    return result
