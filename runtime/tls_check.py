"""Trusted setup only; no project import, secrets, or disabled verification."""
import hashlib
import json
import ssl
import urllib.error
import urllib.request

ctx = ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt')
results = {}
with urllib.request.urlopen('https://pypi.org/', context=ctx, timeout=20) as response:
    if response.status != 200:
        raise RuntimeError('TLS positive control failed')
for host in ('dv-g3b-emudhra.we-have-a-problem.com', 'dv-g3b-aaa-emudhra.we-have-a-problem.com'):
    try:
        urllib.request.urlopen('https://' + host + '/', context=ctx, timeout=20)
    except urllib.error.URLError as error:
        cause = error.reason
        if not isinstance(cause, ssl.SSLCertVerificationError) or cause.verify_code not in (20, 21, 23):
            raise RuntimeError('No specific untrusted-chain/revocation rejection: ' + host) from error
        results[host] = {'verify_code': cause.verify_code, 'reason': cause.verify_message}
    else:
        raise RuntimeError('Compromised chain was accepted: ' + host)
with open('/etc/ssl/certs/ca-certificates.crt', 'rb') as f:
    results['ca_sha256'] = hashlib.sha256(f.read()).hexdigest()
results['openssl'] = ssl.OPENSSL_VERSION
print(json.dumps(results, sort_keys=True))
