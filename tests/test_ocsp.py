# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
import hashlib
from datetime import datetime, timedelta

from asn1crypto import keys, ocsp, util, x509
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPTests(unittest.TestCase):

    def test_parse_request(self):
        with open(os.path.join(fixtures_dir, 'ocsp_request'), 'rb') as f:
            request = ocsp.OCSPRequest.load(f.read())

        tbs_request = request['tbs_request']
        request_list = tbs_request['request_list']
        single_request = request_list[0]
        req_cert = single_request['req_cert']

        self.assertEqual(
            'v1',
            tbs_request['version'].native
        )
        self.assertEqual(
            None,
            tbs_request['requestor_name'].native
        )
        self.assertEqual(
            'sha1',
            req_cert['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            req_cert['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\xAA\x2B\x03\x14\xAF\x64\x2E\x13\x0E\xD6\x92\x25\xE3\xFF\x2A\xBA\xD7\x3D\x62\x30',
            req_cert['issuer_name_hash'].native
        )
        self.assertEqual(
            b'\xDE\xCF\x5C\x50\xB7\xAE\x02\x1F\x15\x17\xAA\x16\xE8\x0D\xB5\x28\x9D\x6A\x5A\xF3',
            req_cert['issuer_key_hash'].native
        )
        self.assertEqual(
            130338219198307073574879940486642352162,
            req_cert['serial_number'].native
        )

    def test_parse_response(self):
        with open(os.path.join(fixtures_dir, 'ocsp_response'), 'rb') as f:
            response = ocsp.OCSPResponse.load(f.read())

        response_bytes = response['response_bytes']
        basic_ocsp_response = response_bytes['response'].parsed
        tbs_response_data = basic_ocsp_response['tbs_response_data']
        responder_id = tbs_response_data['responder_id']
        single_response = tbs_response_data['responses'][0]
        cert_id = single_response['cert_id']
        cert = basic_ocsp_response['certs'][0]

        self.assertEqual(
            'successful',
            response['response_status'].native
        )
        self.assertEqual(
            'basic_ocsp_response',
            response_bytes['response_type'].native
        )
        self.assertEqual(
            'sha1_rsa',
            basic_ocsp_response['signature_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            basic_ocsp_response['signature_algorithm']['parameters'].native
        )
        self.assertEqual(
            'v1',
            tbs_response_data['version'].native
        )
        self.assertEqual(
            b'\x4E\xC5\x63\xD6\xB2\x05\x05\xD7\x76\xF0\x07\xED\xAC\x7D\x5A\x56\x97\x7B\xBD\x3C',
            responder_id.native
        )
        self.assertEqual(
            'by_key',
            responder_id.name
        )
        self.assertEqual(
            datetime(2015, 5, 22, 16, 24, 8, tzinfo=util.timezone.utc),
            tbs_response_data['produced_at'].native
        )
        self.assertEqual(
            'sha1',
            cert_id['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            cert_id['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\xAA\x2B\x03\x14\xAF\x64\x2E\x13\x0E\xD6\x92\x25\xE3\xFF\x2A\xBA\xD7\x3D\x62\x30',
            cert_id['issuer_name_hash'].native
        )
        self.assertEqual(
            b'\xDE\xCF\x5C\x50\xB7\xAE\x02\x1F\x15\x17\xAA\x16\xE8\x0D\xB5\x28\x9D\x6A\x5A\xF3',
            cert_id['issuer_key_hash'].native
        )
        self.assertEqual(
            130338219198307073574879940486642352162,
            cert_id['serial_number'].native
        )
        self.assertEqual(
            datetime(2015, 5, 22, 16, 24, 8, tzinfo=util.timezone.utc),
            single_response['this_update'].native
        )
        self.assertEqual(
            datetime(2015, 5, 29, 16, 24, 8, tzinfo=util.timezone.utc),
            single_response['next_update'].native
        )
        self.assertEqual(
            None,
            single_response['single_extensions'].native
        )
        self.assertEqual(
            None,
            tbs_response_data['response_extensions'].native
        )
        self.assertIsInstance(
            basic_ocsp_response['certs'].native,
            list
        )
        self.assertEqual(
            1,
            len(basic_ocsp_response['certs'])
        )
        self.assertEqual(
            'v3',
            cert['tbs_certificate']['version'].native
        )

    def test_cert_status_native(self):
        status = ocsp.CertStatus.load(b'\x80\x00')
        self.assertEqual('good', status.native)

        status = ocsp.CertStatus(('good', ocsp.StatusGood()))
        self.assertEqual('good', status.native)

        with self.assertRaises(ValueError):
            ocsp.StatusGood('unknown')

        status = ocsp.CertStatus.load(
            b'\xa1\x16\x18\x0f\x32\x30\x31\x38\x31\x30\x30\x33'
            b'\x31\x34\x35\x33\x34\x37\x5a\xa0\x03\x0a\x01\x01'
        )
        self.assertIsInstance(
            status.native,
            util.OrderedDict
        )

        status = ocsp.CertStatus.load(b'\x82\x00')
        self.assertEqual('unknown', status.native)

        status = ocsp.CertStatus(('unknown', ocsp.StatusUnknown()))
        self.assertEqual('unknown', status.native)

        with self.assertRaises(ValueError):
            ocsp.StatusUnknown('good')


# Sentinel meaning the SingleResponse should omit the optional nextUpdate field
_NO_NEXT_UPDATE = object()


def _general_time(value):
    return x509.Time(
        name='general_time',
        value=x509.GeneralizedTime(value)
    )


def _make_cert(subject_cn, serial, issuer_cn, key_marker):
    """
    Builds a minimal, self-contained Certificate object without ever touching a
    network or a real cryptographic provider. The public key contents are
    deterministic marker values, which is all the CertID hashing requires.
    """

    tbs_certificate = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': x509.Name.build({
            'country_name': 'US',
            'organization_name': 'Test CA',
            'common_name': issuer_cn,
        }),
        'validity': {
            'not_before': _general_time(datetime(2015, 1, 1, tzinfo=util.timezone.utc)),
            'not_after': _general_time(datetime(2035, 1, 1, tzinfo=util.timezone.utc)),
        },
        'subject': x509.Name.build({
            'country_name': 'US',
            'organization_name': 'Test CA',
            'common_name': subject_cn,
        }),
        'subject_public_key_info': {
            'algorithm': {'algorithm': 'rsa'},
            'public_key': keys.RSAPublicKey({
                'modulus': util.int_from_bytes(key_marker),
                'public_exponent': 65537,
            }),
        },
    })
    return x509.Certificate({
        'tbs_certificate': tbs_certificate,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': b'\x00\x00',
    })

def _make_cert_id(cert, issuer, hash_algo='sha256'):
    issuer_name_hash = hashlib.new(
        hash_algo, issuer.subject.dump()
    ).digest()
    issuer_key_hash = hashlib.new(
        hash_algo,
        byte_cls(issuer.public_key['public_key'])
    ).digest()
    return ocsp.CertId({
        'hash_algorithm': {'algorithm': hash_algo},
        'issuer_name_hash': issuer_name_hash,
        'issuer_key_hash': issuer_key_hash,
        'serial_number': cert.serial_number,
    })


def _make_request(cert_id, nonce=None):
    tbs_kwargs = {
        'request_list': [ocsp.Request({'req_cert': cert_id})]
    }
    if nonce is not None:
        tbs_kwargs['request_extensions'] = [
            {'extn_id': 'nonce', 'extn_value': nonce}
        ]
    return ocsp.OCSPRequest({
        'tbs_request': ocsp.TBSRequest(tbs_kwargs)
    })


def _make_single_response(cert_id, this_update, next_update=_NO_NEXT_UPDATE,
                          status='good', revocation_time=None,
                          revocation_reason=None):
    if status == 'good':
        cert_status = ('good', ocsp.StatusGood())
    elif status == 'unknown':
        cert_status = ('unknown', ocsp.StatusUnknown())
    else:
        revoked_info = {
            'revocation_time': revocation_time or this_update
        }
        if revocation_reason is not None:
            revoked_info['revocation_reason'] = revocation_reason
        cert_status = ('revoked', revoked_info)

    kwargs = {
        'cert_id': cert_id,
        'cert_status': cert_status,
        'this_update': this_update,
    }
    if next_update is not _NO_NEXT_UPDATE:
        kwargs['next_update'] = next_update
    return ocsp.SingleResponse(kwargs)


def _make_response(single_responses, produced_at, nonce=None,
                   response_status='successful'):
    if response_status != 'successful':
        return ocsp.OCSPResponse({'response_status': response_status})

    response_data_kwargs = {
        'responder_id': ('by_key', b'\x52' * 20),
        'produced_at': produced_at,
        'responses': single_responses,
    }
    if nonce is not None:
        response_data_kwargs['response_extensions'] = [
            {'extn_id': 'nonce', 'extn_value': nonce}
        ]

    basic_ocsp_response = ocsp.BasicOCSPResponse({
        'tbs_response_data': ocsp.ResponseData(response_data_kwargs),
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x00\x00',
    })
    return ocsp.OCSPResponse({
        'response_status': 'successful',
        'response_bytes': {
            'response_type': 'basic_ocsp_response',
            'response': ocsp.ParsableOctetString(
                parsed=basic_ocsp_response
            ),
        },
    })


class OCSPResponseAssessmentTests(unittest.TestCase):
    # Two distinct issuers and two leaf certificates that deliberately share a
    # serial number, so that serial alone can never establish association
    @classmethod
    def setUpClass(cls):
        cls.issuer_a = _make_cert('Issuer A', 1001, 'Issuer A', b'A' * 256)
        cls.issuer_b = _make_cert('Issuer B', 1002, 'Issuer B', b'B' * 256)
        cls.cert_a = _make_cert('Shared Serial Leaf', 777, 'Issuer A', b'L' * 256)
        cls.cert_b = _make_cert('Shared Serial Leaf', 777, 'Issuer B', b'M' * 256)
        cls.cert_id_a = _make_cert_id(cls.cert_a, cls.issuer_a)
        cls.cert_id_b = _make_cert_id(cls.cert_b, cls.issuer_b)

        cls.this_update = datetime(2020, 1, 1, 12, 0, 0, tzinfo=util.timezone.utc)
        cls.next_update = cls.this_update + timedelta(days=7)
        cls.produced_at = cls.this_update
        cls.max_age = timedelta(hours=1)

    def _allow(self, basic_ocsp_response, cert, issuer):
        return True

    def _deny(self, basic_ocsp_response, cert, issuer):
        return False

    def _boom(self, basic_ocsp_response, cert, issuer):
        raise RuntimeError('signature verification failed')
    def _assess(self, response, evaluation_time=None, request=None, **kwargs):
        if evaluation_time is None:
            evaluation_time = self.this_update
        callback = kwargs.pop('responder_signature_callback', self._allow)
        return ocsp.assess_ocsp_response(
            self.cert_a,
            self.issuer_a,
            response,
            evaluation_time,
            request=request,
            responder_signature_callback=callback,
            **kwargs
        )

    def _good_response(self, cert_id=None, nonce=None):
        if cert_id is None:
            cert_id = self.cert_id_a
        return _make_response(
            [_make_single_response(cert_id, self.this_update, self.next_update)],
            self.produced_at,
            nonce=nonce
        )

    def test_shared_serial_number(self):
        self.assertEqual(self.cert_a.serial_number, self.cert_b.serial_number)
        self.assertNotEqual(
            self.issuer_a.subject.dump(),
            self.issuer_b.subject.dump()
        )
        self.assertNotEqual(
            self.cert_id_a.dump(),
            self.cert_id_b.dump()
        )

    def test_good_response_associated_with_request(self):
        request = _make_request(self.cert_id_a, nonce=b'nonce-1')
        response = self._good_response(nonce=b'nonce-1')

        result = self._assess(response, request=request)

        self.assertEqual(ocsp.STATUS_GOOD, result.status)
        self.assertTrue(result.trusted)
        self.assertEqual(self.this_update, result.this_update)
        self.assertEqual(self.next_update, result.next_update)
        self.assertEqual(self.produced_at, result.produced_at)
        self.assertIsNone(result.error)

    def test_same_serial_different_issuer_is_no_match(self):
        request = _make_request(self.cert_id_a)
        response = self._good_response(cert_id=self.cert_id_b)

        result = self._assess(response, request=request)

        self.assertEqual(ocsp.STATUS_NO_MATCH, result.status)
        self.assertFalse(result.trusted)

    def test_response_for_wrong_serial_is_no_match(self):
        cert_id = ocsp.CertId({
            'hash_algorithm': {'algorithm': 'sha256'},
            'issuer_name_hash': self.cert_id_a['issuer_name_hash'].native,
            'issuer_key_hash': self.cert_id_a['issuer_key_hash'].native,
            'serial_number': self.cert_a.serial_number + 1,
        })
        response = self._good_response(cert_id=cert_id)

        result = self._assess(response)

        self.assertEqual(ocsp.STATUS_NO_MATCH, result.status)

    def test_response_for_unrequested_cert_raises(self):
        # The request asks about issuer A's certificate, but the assessment is
        # for issuer B's same-serial-number certificate
        request = _make_request(self.cert_id_a)
        response = self._good_response(cert_id=self.cert_id_b)

        with self.assertRaises(ocsp.OCSPResponseAssociationError):
            ocsp.assess_ocsp_response(
                self.cert_b,
                self.issuer_b,
                response,
                self.this_update,
                request=request,
                responder_signature_callback=self._allow
            )

    def test_revoked(self):
        revocation_time = self.this_update - timedelta(days=2)
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a,
                    self.this_update,
                    self.next_update,
                    status='revoked',
                    revocation_time=revocation_time,
                    revocation_reason='key_compromise'
                )
            ],
            self.produced_at
        )

        result = self._assess(response)

        self.assertEqual(ocsp.STATUS_REVOKED, result.status)
        self.assertTrue(result.trusted)
        self.assertEqual(revocation_time, result.revocation_time)
        self.assertEqual('key_compromise', result.revocation_reason)

    def test_unknown(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a,
                    self.this_update,
                    self.next_update,
                    status='unknown'
                )
            ],
            self.produced_at
        )

        result = self._assess(response)

        self.assertEqual(ocsp.STATUS_UNKNOWN, result.status)
        self.assertTrue(result.trusted)

    def test_non_successful_response_raises(self):
        response = _make_response([], self.produced_at, response_status='unauthorized')

        with self.assertRaises(ocsp.OCSPResponseStatusError):
            self._assess(response)

    def test_nonce_mismatch_raises_under_match_if_sent(self):
        request = _make_request(self.cert_id_a, nonce=b'request-nonce')
        response = self._good_response(nonce=b'response-nonce')

        with self.assertRaises(ocsp.OCSPResponseAssociationError):
            self._assess(response, request=request)

    def test_missing_response_nonce_raises_under_match_if_sent(self):
        request = _make_request(self.cert_id_a, nonce=b'request-nonce')
        response = self._good_response()

        with self.assertRaises(ocsp.OCSPResponseAssociationError):
            self._assess(response, request=request)

    def test_nonce_not_required_when_request_omits_it(self):
        request = _make_request(self.cert_id_a)
        response = self._good_response()

        result = self._assess(response, request=request)

        self.assertEqual(ocsp.STATUS_GOOD, result.status)

    def test_nonce_ignore_policy(self):
        request = _make_request(self.cert_id_a, nonce=b'request-nonce')
        response = self._good_response(nonce=b'response-nonce')

        result = self._assess(
            response,
            request=request,
            nonce_policy=ocsp.NONCE_IGNORE
        )

        self.assertEqual(ocsp.STATUS_GOOD, result.status)

    def test_nonce_require_policy(self):
        request = _make_request(self.cert_id_a)
        response = self._good_response()

        with self.assertRaises(ocsp.OCSPResponseAssociationError):
            self._assess(
                response,
                request=request,
                nonce_policy=ocsp.NONCE_REQUIRE
            )

        request = _make_request(self.cert_id_a, nonce=b'nonce')
        response = self._good_response(nonce=b'nonce')
        result = self._assess(
            response,
            request=request,
            nonce_policy=ocsp.NONCE_REQUIRE
        )
        self.assertEqual(ocsp.STATUS_GOOD, result.status)

    def test_contradictory_single_responses_raise(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a, self.this_update, self.next_update
                ),
                _make_single_response(
                    self.cert_id_a,
                    self.this_update,
                    self.next_update,
                    status='revoked',
                    revocation_time=self.this_update
                ),
            ],
            self.produced_at
        )

        with self.assertRaises(ocsp.OCSPResponseAssociationError):
            self._assess(response)

    def test_duplicate_consistent_single_responses_allowed(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a, self.this_update, self.next_update
                ),
                _make_single_response(
                    self.cert_id_a, self.this_update, self.next_update
                ),
            ],
            self.produced_at
        )

        result = self._assess(response)

        self.assertEqual(ocsp.STATUS_GOOD, result.status)
        self.assertTrue(result.trusted)

    def test_target_status_selected_among_other_certificates(self):
        # The other issuer's same-serial certificate is revoked and appears
        # first, but it must not be used as the answer for the target
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_b,
                    self.this_update,
                    self.next_update,
                    status='revoked',
                    revocation_time=self.this_update
                ),
                _make_single_response(
                    self.cert_id_a, self.this_update, self.next_update
                ),
            ],
            self.produced_at
        )

        result = self._assess(response)

        self.assertEqual(ocsp.STATUS_GOOD, result.status)
        self.assertTrue(result.trusted)
        self.assertIsNone(result.revocation_time)

    def test_repeated_status_uses_most_recent_this_update(self):
        older = self.this_update
        newer = self.this_update + timedelta(hours=6)
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a, older, older + timedelta(days=7)
                ),
                _make_single_response(
                    self.cert_id_a, newer, newer + timedelta(days=7)
                ),
            ],
            self.produced_at
        )

        result = self._assess(response, evaluation_time=newer)

        self.assertEqual(ocsp.STATUS_GOOD, result.status)
        self.assertEqual(newer, result.this_update)

    def test_expired_via_next_update_boundary(self):
        response = self._good_response()

        # Exactly at nextUpdate the answer is still fresh
        result = self._assess(response, evaluation_time=self.next_update)
        self.assertEqual(ocsp.STATUS_GOOD, result.status)

        # Five minutes after is saved by the default five minute skew
        result = self._assess(
            response,
            evaluation_time=self.next_update + timedelta(minutes=5)
        )
        self.assertEqual(ocsp.STATUS_GOOD, result.status)

        # One second beyond the skew window is expired
        result = self._assess(
            response,
            evaluation_time=self.next_update + timedelta(minutes=5, seconds=1)
        )
        self.assertEqual(ocsp.STATUS_EXPIRED, result.status)
        self.assertFalse(result.trusted)

    def test_explicit_skew_boundary(self):
        response = self._good_response()
        skew = timedelta(minutes=1)

        result = self._assess(
            response,
            evaluation_time=self.next_update + timedelta(seconds=60),
            skew=skew
        )
        self.assertEqual(ocsp.STATUS_GOOD, result.status)

        result = self._assess(
            response,
            evaluation_time=self.next_update + timedelta(seconds=61),
            skew=skew
        )
        self.assertEqual(ocsp.STATUS_EXPIRED, result.status)

    def test_missing_next_update_requires_max_age(self):
        response = _make_response(
            [_make_single_response(self.cert_id_a, self.this_update)],
            self.produced_at
        )

        with self.assertRaises(ocsp.OCSPResponseStatusError):
            self._assess(response)

    def test_missing_next_update_max_age_boundary(self):
        response = _make_response(
            [_make_single_response(self.cert_id_a, self.this_update)],
            self.produced_at
        )

        # Exactly thisUpdate + max_age is still acceptable
        result = self._assess(
            response,
            evaluation_time=self.this_update + self.max_age,
            max_age=self.max_age
        )
        self.assertEqual(ocsp.STATUS_GOOD, result.status)

        # Boundary plus the skew window is still acceptable
        result = self._assess(
            response,
            evaluation_time=self.this_update + self.max_age + timedelta(minutes=5),
            max_age=self.max_age
        )
        self.assertEqual(ocsp.STATUS_GOOD, result.status)

        # Beyond the age limit plus skew is expired
        result = self._assess(
            response,
            evaluation_time=self.this_update + self.max_age + timedelta(minutes=5, seconds=1),
            max_age=self.max_age
        )
        self.assertEqual(ocsp.STATUS_EXPIRED, result.status)

    def test_future_this_update_raises(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a,
                    self.this_update + timedelta(hours=1),
                    self.next_update
                )
            ],
            self.produced_at
        )

        with self.assertRaises(ocsp.OCSPResponseStatusError):
            self._assess(response)

    def test_future_this_update_within_skew_is_accepted(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a,
                    self.this_update + timedelta(minutes=3),
                    self.next_update
                )
            ],
            self.produced_at
        )

        result = self._assess(response)

        self.assertEqual(ocsp.STATUS_GOOD, result.status)

    def test_future_produced_at_raises(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a, self.this_update, self.next_update
                )
            ],
            self.produced_at + timedelta(hours=1)
        )

        with self.assertRaises(ocsp.OCSPResponseStatusError):
            self._assess(response)

    def test_signature_callback_false_downgrades_good(self):
        response = self._good_response()

        result = self._assess(
            response,
            responder_signature_callback=self._deny
        )

        self.assertEqual(ocsp.STATUS_UNKNOWN, result.status)
        self.assertFalse(result.trusted)
        self.assertIsNotNone(result.error)

    def test_signature_callback_exception_downgrades_good(self):
        response = self._good_response()

        result = self._assess(
            response,
            responder_signature_callback=self._boom
        )

        self.assertEqual(ocsp.STATUS_UNKNOWN, result.status)
        self.assertFalse(result.trusted)
        self.assertIn('RuntimeError', result.error)

    def test_signature_callback_false_revoked_is_untrusted(self):
        response = _make_response(
            [
                _make_single_response(
                    self.cert_id_a,
                    self.this_update,
                    self.next_update,
                    status='revoked',
                    revocation_time=self.this_update
                )
            ],
            self.produced_at
        )

        result = self._assess(
            response,
            responder_signature_callback=self._deny
        )

        self.assertEqual(ocsp.STATUS_REVOKED, result.status)
        self.assertFalse(result.trusted)

    def test_signature_callback_arguments(self):
        seen = {}

        def callback(basic_ocsp_response, cert, issuer):
            seen['basic_ocsp_response'] = basic_ocsp_response
            seen['cert'] = cert
            seen['issuer'] = issuer
            return True

        self._assess(self._good_response(), responder_signature_callback=callback)

        self.assertIsInstance(
            seen['basic_ocsp_response'],
            ocsp.BasicOCSPResponse
        )
        self.assertIs(seen['cert'], self.cert_a)
        self.assertIs(seen['issuer'], self.issuer_a)

    def test_expired_and_no_match_do_not_invoke_callback(self):
        invoked = []

        def callback(basic_ocsp_response, cert, issuer):
            invoked.append(True)
            return True

        expired_response = self._good_response()
        result = self._assess(
            expired_response,
            evaluation_time=self.next_update + timedelta(days=1),
            responder_signature_callback=callback
        )
        self.assertEqual(ocsp.STATUS_EXPIRED, result.status)

        no_match_response = self._good_response(cert_id=self.cert_id_b)
        result = self._assess(
            no_match_response,
            responder_signature_callback=callback
        )
        self.assertEqual(ocsp.STATUS_NO_MATCH, result.status)

        self.assertEqual([], invoked)

    def test_naive_evaluation_time_treated_as_utc(self):
        response = self._good_response()

        result = self._assess(
            response,
            evaluation_time=datetime(2020, 1, 1, 12, 0, 0)
        )

        self.assertEqual(ocsp.STATUS_GOOD, result.status)

    def test_invalid_arguments(self):
        response = self._good_response()

        with self.assertRaises(ValueError):
            ocsp.assess_ocsp_response(
                b'not-a-cert',
                self.issuer_a,
                response,
                self.this_update,
                responder_signature_callback=self._allow
            )

        with self.assertRaises(ValueError):
            ocsp.assess_ocsp_response(
                self.cert_a,
                self.issuer_a,
                response,
                self.this_update
            )

        with self.assertRaises(ValueError):
            self._assess(response, nonce_policy='bogus')
