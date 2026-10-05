# coding: utf-8
"""
Generates local ASN.1 fixtures for tests/test_tsp.py verification checks.

The fixtures are syntactically valid RFC 3161 TimeStampReq/TimeStampResp and
CMS SignedData objects, built with a small (512-bit) RSA public key. The
actual CMS signature bytes are a fixed dummy value: cryptographic signature
and chain validation are the caller's responsibility in production (and a
stub callback in the tests), while the local correspondence checks are what
this suite exercises.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os

from asn1crypto import cms, tsp, x509, keys, algos
from asn1crypto.core import ParsableOctetString

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

POLICY = '1.2.3.4.5'
DIGEST_ALGO = 'sha256'


def _rsa_keypair():
    # Small primes chosen for a deterministic 511-bit modulus; fixture data is
    # never used with real cryptography.
    p = 0x00D237A9D8E2E65C29B0CC3F7F2E7C0B3A41C9F5E3A8B1C7D6E5F4031201F0E7F1
    q = 0x00C9B8A7F6E5D4C3B2A19087F6E5D4C3B2A19087F6E5D4C3B2A19087F6E5D4B3
    e = 65537
    n = p * q
    return n, e


def _certificate(subject_cn, tsa_eku, include_ski=True, serial=1):
    n, e = _rsa_keypair()
    public_key = keys.RSAPublicKey({'modulus': n, 'public_exponent': e})
    spki = keys.PublicKeyInfo({
        'algorithm': keys.PublicKeyAlgorithm({'algorithm': 'rsa'}),
        'public_key': public_key,
    })
    name = x509.Name.build({
        'country_name': 'US',
        'organization_name': 'Test Org',
        'common_name': subject_cn,
    })
    extensions = []
    if include_ski:
        extensions.append(x509.Extension({
            'extn_id': 'key_identifier',
            'critical': False,
            'extn_value': b'\x11\x22\x33\x44\x55\x66\x77\x88',
        }))
    extensions.append(x509.Extension({
        'extn_id': 'key_usage',
        'critical': True,
        'extn_value': x509.KeyUsage(set(['digital_signature'])),
    }))
    if tsa_eku:
        eku_value = x509.ExtKeyUsageSyntax(['time_stamping'])
    else:
        eku_value = x509.ExtKeyUsageSyntax(['server_auth'])
    extensions.append(x509.Extension({
        'extn_id': 'extended_key_usage',
        'critical': True,
        'extn_value': eku_value,
    }))
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial,
        'signature': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'issuer': name,
        'validity': {
            'not_before': x509.Time({'utc_time': '200101000000Z'}),
            'not_after': x509.Time({'utc_time': '490101000000Z'}),
        },
        'subject': name,
        'subject_public_key_info': spki,
        'extensions': extensions,
    })
    return x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'signature_value': b'\x00' * 64,
    }), name


def _request(message_digest, nonce=None, policy=None):
    fields = {
        'version': 'v1',
        'message_imprint': {
            'hash_algorithm': {'algorithm': DIGEST_ALGO},
            'hashed_message': message_digest,
        },
        'cert_req': True,
    }
    if nonce is not None:
        fields['nonce'] = nonce
    if policy is not None:
        fields['req_policy'] = policy
    return tsp.TimeStampReq(fields)


def _response(message_digest, nonce, policy, certificate, subject_name,
              tsa_name_included=True, message_digest_attr_correct=True,
              include_signing_cert_attr=True, signer_serial=1):
    tst_kwargs = {
        'version': 'v1',
        'policy': policy,
        'message_imprint': {
            'hash_algorithm': {'algorithm': DIGEST_ALGO},
            'hashed_message': message_digest,
        },
        'serial_number': 12345,
        'gen_time': '20250601120000Z',
        'accuracy': {'seconds': 5, 'millis': 250, 'micros': 100},
        'ordering': True,
    }
    if nonce is not None:
        tst_kwargs['nonce'] = nonce
    if tsa_name_included:
        tst_kwargs['tsa'] = x509.GeneralName({'directory_name': subject_name})
    tst_info = tsp.TSTInfo(tst_kwargs)
    econtent = tst_info.dump()

    attrs = []
    attrs.append(cms.CMSAttribute({
        'type': 'content_type',
        'values': [cms.ContentType('tst_info')],
    }))
    attrs.append(cms.CMSAttribute({
        'type': 'signing_time',
        'values': [cms.Time({'utc_time': '250601120000Z'})],
    }))
    calculated = hashlib.sha256(econtent).digest()
    if not message_digest_attr_correct:
        calculated = b'\xff' * 32
    attrs.append(cms.CMSAttribute({
        'type': 'message_digest',
        'values': [calculated],
    }))
    if include_signing_cert_attr:
        cert_hash = hashlib.sha256(certificate.dump()).digest()
        attrs.append(cms.CMSAttribute({
            'type': 'signing_certificate_v2',
            'values': [tsp.SigningCertificateV2({
                'certs': [tsp.ESSCertIDv2({
                    'hash_algorithm': {'algorithm': 'sha256'},
                    'cert_hash': cert_hash,
                })],
            })],
        }))

    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': {
                'issuer': subject_name,
                'serial_number': signer_serial,
            },
        }),
        'digest_algorithm': {'algorithm': DIGEST_ALGO},
        'signed_attrs': cms.CMSAttributes(attrs),
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x00' * 64,
    })

    signed_data = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': [algos.DigestAlgorithm({'algorithm': DIGEST_ALGO})],
        'encap_content_info': cms.EncapsulatedContentInfo({
            'content_type': 'tst_info',
            'content': ParsableOctetString(econtent),
        }),
        'certificates': [certificate],
        'signer_infos': [signer_info],
    })
    token = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })
    return tsp.TimeStampResp({
        'status': tsp.PKIStatusInfo({'status': 'granted'}),
        'time_stamp_token': token,
    })


def _write(name, der):
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, 'wb') as f:
        f.write(der)
    print('wrote %s (%d bytes)' % (path, len(der)))


def main():
    message_digest = hashlib.sha256(b'original document contents').digest()
    nonce = 9876543210

    request = _request(message_digest, nonce=nonce, policy=POLICY)
    _write('tsp_verify_request', request.dump())

    certificate, subject_name = _certificate('Test TSA', tsa_eku=True)

    valid = _response(
        message_digest, nonce, POLICY, certificate, subject_name
    )
    _write('tsp_verify_response.der', valid.dump())

    bad_digest = _response(
        hashlib.sha256(b'different document contents').digest(),
        nonce, POLICY, certificate, subject_name
    )
    _write('tsp_verify_response_bad_digest.der', bad_digest.dump())

    bad_nonce = _response(
        message_digest, nonce + 1, POLICY, certificate, subject_name
    )
    _write('tsp_verify_response_bad_nonce.der', bad_nonce.dump())

    bad_certificate, bad_subject_name = _certificate(
        'Not A TSA', tsa_eku=False, serial=2
    )
    bad_purpose = _response(
        message_digest, nonce, POLICY, bad_certificate, bad_subject_name,
        signer_serial=2
    )
    _write('tsp_verify_response_bad_tsa_purpose.der', bad_purpose.dump())

    bad_policy = _response(
        message_digest, nonce, '1.9.9.9', certificate, subject_name
    )
    _write('tsp_verify_response_bad_policy.der', bad_policy.dump())

    # Raw rejection with status only and NO TimeStampToken
    status_info = tsp.PKIStatusInfo({
        'status': 'rejection',
        'fail_info': tsp.PKIFailureInfo(set(['bad_request'])),
    })
    rejection = tsp.TimeStampResp({'status': status_info})
    _write('tsp_verify_rejection.der', rejection.dump())


if __name__ == '__main__':
    main()
