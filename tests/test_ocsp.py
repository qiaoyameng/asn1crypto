# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
from datetime import datetime, timedelta
import hashlib

from asn1crypto import keys, ocsp, util, x509
from asn1crypto.core import OctetString
from asn1crypto.keys import RSAPublicKey
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

    def test_response_must_match_original_request_and_issuer(self):
        test_data = self._build_test_data()
        evaluation_time = test_data['this_update'] + timedelta(minutes=30)

        self.assertEqual(
            test_data['certificate'].serial_number,
            test_data['other_certificate'].serial_number
        )
        self.assertNotEqual(
            test_data['issuer_one'].subject.dump(),
            test_data['issuer_two'].subject.dump()
        )

        result = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            test_data['response'](),
            evaluation_time,
            self._allow_responder,
        )
        self.assertEqual('good', result.status)
        self.assertTrue(result.trusted_good)

        wrong_issuer_result = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_two'],
            test_data['request'],
            test_data['response'](),
            evaluation_time,
            self._allow_responder,
        )
        self.assertEqual('no_match', wrong_issuer_result.status)
        self.assertFalse(wrong_issuer_result.trusted_good)

        other_cert_result = ocsp.check_ocsp_response(
            test_data['other_certificate'],
            test_data['issuer_two'],
            test_data['request'],
            test_data['response'](cert_id=test_data['cert_id_two']),
            evaluation_time,
            self._allow_responder,
        )
        self.assertEqual('no_match', other_cert_result.status)

    def test_response_without_next_update_uses_max_age_boundary(self):
        test_data = self._build_test_data(nonce=None)
        this_update = test_data['this_update']
        response = test_data['response'](next_update=None)
        verifier = self._allow_responder

        at_boundary = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update + timedelta(hours=1),
            verifier,
            max_age=timedelta(hours=1)
        )
        self.assertEqual('good', at_boundary.status)

        after_boundary = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update + timedelta(hours=1, seconds=1),
            verifier,
            max_age=timedelta(hours=1)
        )
        self.assertEqual('expired', after_boundary.status)

        without_policy = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update + timedelta(hours=1),
            self._allow_responder,
        )
        self.assertEqual('expired', without_policy.status)
        self.assertEqual('no_next_update_and_no_max_age', without_policy.reason)

    def test_next_update_boundary_uses_explicit_clock_skew(self):
        test_data = self._build_test_data(nonce=None)
        this_update = test_data['this_update']
        response = test_data['response'](
            next_update=this_update + timedelta(hours=1)
        )
        verifier = self._allow_responder

        at_boundary = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update + timedelta(hours=1),
            verifier,
            clock_skew=timedelta(minutes=5)
        )
        self.assertEqual('good', at_boundary.status)

        within_skew = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update + timedelta(hours=1, minutes=4, seconds=59),
            verifier,
            clock_skew=timedelta(minutes=5)
        )
        self.assertEqual('good', within_skew.status)

        outside_skew = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update + timedelta(hours=1, minutes=5, seconds=1),
            verifier,
            clock_skew=timedelta(minutes=5)
        )
        self.assertEqual('expired', outside_skew.status)

    def test_produced_at_respects_explicit_clock_skew(self):
        test_data = self._build_test_data(nonce=None)
        this_update = test_data['this_update']
        response = test_data['response'](
            next_update=this_update + timedelta(hours=1)
        )
        verifier = self._allow_responder
        skew = timedelta(minutes=5)

        at_boundary = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update - skew,
            verifier,
            clock_skew=skew
        )
        self.assertEqual('good', at_boundary.status)

        after_boundary = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            this_update - skew - timedelta(seconds=1),
            verifier,
            clock_skew=skew
        )
        self.assertEqual('invalid', after_boundary.status)
        self.assertEqual('response_from_future', after_boundary.reason)

    def test_contradictory_duplicate_responses_are_not_selected(self):
        test_data = self._build_test_data()
        response = test_data['response'](statuses=('good', 'revoked'))

        result = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            test_data['this_update'],
            self._allow_responder,
        )
        self.assertEqual('invalid', result.status)
        self.assertEqual('contradictory_single_responses', result.reason)

    def test_responder_callback_failure_never_returns_good(self):
        test_data = self._build_test_data()
        args = (
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            test_data['response'](),
            test_data['this_update'],
        )

        def failing_verifier(basic_response, certificate, issuer):
            raise ValueError('signature is invalid')

        failure_result = ocsp.check_ocsp_response(
            *args,
            responder_verifier=failing_verifier
        )
        self.assertEqual('unauthorized', failure_result.status)
        self.assertFalse(failure_result.trusted_good)

        rejected_result = ocsp.check_ocsp_response(
            *args,
            responder_verifier=self._deny_responder
        )
        self.assertEqual('unauthorized', rejected_result.status)
        self.assertFalse(rejected_result.trusted_good)

    def test_nonce_mismatch_is_not_a_matching_response(self):
        test_data = self._build_test_data(nonce=b'expected nonce')
        response = test_data['response'](response_nonce=b'different nonce')

        result = ocsp.check_ocsp_response(
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
            response,
            test_data['this_update'],
            self._allow_responder,
        )
        self.assertEqual('no_match', result.status)
        self.assertEqual('nonce_mismatch', result.reason)

    def test_revoked_and_unknown_statuses_are_distinguished(self):
        test_data = self._build_test_data(nonce=None)
        verifier = self._allow_responder
        args = (
            test_data['certificate'],
            test_data['issuer_one'],
            test_data['request'],
        )

        revoked = ocsp.check_ocsp_response(
            *(args + (test_data['response'](statuses=('revoked',)),)),
            evaluation_time=test_data['this_update'],
            responder_verifier=verifier
        )
        self.assertEqual('revoked', revoked.status)
        self.assertEqual(test_data['this_update'], revoked.revocation_time)
        self.assertTrue(revoked.trusted)

        unknown = ocsp.check_ocsp_response(
            *(args + (test_data['response'](statuses=('unknown',)),)),
            evaluation_time=test_data['this_update'],
            responder_verifier=verifier
        )
        self.assertEqual('unknown', unknown.status)
        self.assertIsNone(unknown.revocation_time)
        self.assertTrue(unknown.trusted)

    def test_checker_accepts_der_objects_and_aware_evaluation_time(self):
        test_data = self._build_test_data()
        shanghai = util.create_timezone(timedelta(hours=8))
        evaluation_time = (
            test_data['this_update'] + timedelta(minutes=30)
        ).astimezone(shanghai)

        result = ocsp.OCSPResponseChecker().check(
            test_data['certificate'].dump(),
            test_data['issuer_one'].dump(),
            test_data['request'].dump(),
            test_data['response']().dump(),
            evaluation_time,
            responder_verifier=self._allow_responder
        )
        self.assertEqual('good', result.status)

    @staticmethod
    def _allow_responder(basic_response, certificate, issuer):
        return True

    @staticmethod
    def _deny_responder(basic_response, certificate, issuer):
        return False

    def _build_test_data(self, nonce=b'request nonce'):
        issuer_one = self._certificate(
            x509.Name.build({'common_name': 'Issuer One'}),
            x509.Name.build({'common_name': 'Issuer One'}),
            1,
            self._public_key(1001)
        )
        issuer_two = self._certificate(
            x509.Name.build({'common_name': 'Issuer Two'}),
            x509.Name.build({'common_name': 'Issuer Two'}),
            1,
            self._public_key(1002)
        )
        subject = x509.Name.build({'common_name': 'Target Certificate'})
        certificate = self._certificate(
            subject,
            issuer_one.subject,
            0x123456789,
            self._public_key(2001)
        )
        other_certificate = self._certificate(
            subject,
            issuer_two.subject,
            0x123456789,
            self._public_key(2002)
        )

        cert_id_one = self._cert_id(certificate, issuer_one)
        cert_id_two = self._cert_id(other_certificate, issuer_two)
        request_extensions = None
        if nonce is not None:
            request_extensions = [self._nonce_extension(nonce)]
        request = ocsp.OCSPRequest({
            'tbs_request': {
                'request_list': [{'req_cert': cert_id_one}],
                'request_extensions': request_extensions,
            },
        })
        this_update = datetime(2020, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

        missing_next_update = object()

        def response(statuses=('good',), cert_id=None,
                    next_update=missing_next_update,
                    response_nonce=None):
            if cert_id is None:
                cert_id = cert_id_one
            if next_update is missing_next_update:
                next_update = this_update + timedelta(hours=1)
            if response_nonce is None:
                response_nonce = nonce
            response_extensions = None
            if response_nonce is not None:
                response_extensions = [self._nonce_extension(response_nonce)]
            basic_response = ocsp.BasicOCSPResponse({
                'tbs_response_data': {
                    'responder_id': ('by_key', b'responder-key'),
                    'produced_at': this_update,
                    'responses': [
                        self._single_response(
                            status, cert_id, this_update, next_update
                        )
                        for status in statuses
                    ],
                    'response_extensions': response_extensions,
                },
                'signature_algorithm': {'algorithm': 'sha256_rsa'},
                'signature': b'disabled-test-signature',
            })
            return ocsp.OCSPResponse({
                'response_status': 'successful',
                'response_bytes': {
                    'response_type': 'basic_ocsp_response',
                    'response': basic_response,
                },
            })

        return {
            'issuer_one': issuer_one,
            'issuer_two': issuer_two,
            'certificate': certificate,
            'other_certificate': other_certificate,
            'cert_id_one': cert_id_one,
            'cert_id_two': cert_id_two,
            'request': request,
            'response': response,
            'this_update': this_update,
        }

    @staticmethod
    def _public_key(seed):
        rsa_public_key = RSAPublicKey()
        rsa_public_key['modulus'] = (1 << 2047) + seed
        rsa_public_key['public_exponent'] = 65537
        public_key = keys.PublicKeyInfo()
        public_key['algorithm'] = {'algorithm': 'rsa'}
        public_key['public_key'] = rsa_public_key
        return public_key

    @staticmethod
    def _certificate(subject, issuer, serial_number, public_key):
        not_before = datetime(2019, 1, 1, tzinfo=util.timezone.utc)
        not_after = datetime(2029, 1, 1, tzinfo=util.timezone.utc)
        tbs_certificate = x509.TbsCertificate({
            'version': 'v3',
            'serial_number': serial_number,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': issuer,
            'validity': {
                'not_before': ('general_time', not_before),
                'not_after': ('general_time', not_after),
            },
            'subject': subject,
            'subject_public_key_info': public_key,
        })
        certificate = x509.Certificate()
        certificate['tbs_certificate'] = tbs_certificate
        certificate['signature_algorithm'] = {'algorithm': 'sha256_rsa'}
        certificate['signature_value'] = b'\x00' * 256
        return certificate

    @staticmethod
    def _cert_id(certificate, issuer_certificate, algorithm='sha256'):
        name_hash = hashlib.new(
            algorithm,
            issuer_certificate.subject.dump()
        ).digest()
        key_hash = hashlib.new(
            algorithm,
            issuer_certificate.public_key['public_key'].contents
        ).digest()
        return ocsp.CertId({
            'hash_algorithm': {'algorithm': algorithm},
            'issuer_name_hash': name_hash,
            'issuer_key_hash': key_hash,
            'serial_number': certificate.serial_number,
        })

    @staticmethod
    def _single_response(status, cert_id, this_update, next_update):
        if status == 'good':
            cert_status = ('good', ocsp.StatusGood())
        elif status == 'revoked':
            cert_status = ('revoked', {'revocation_time': this_update})
        else:
            cert_status = ('unknown', ocsp.StatusUnknown())
        value = {
            'cert_id': cert_id,
            'cert_status': cert_status,
            'this_update': this_update,
            'next_update': next_update,
        }
        return ocsp.SingleResponse(value)

    @staticmethod
    def _nonce_extension(value):
        return {
            'extn_id': 'nonce',
            'extn_value': OctetString(value),
        }
