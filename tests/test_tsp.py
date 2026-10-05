# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
import hashlib
from datetime import datetime

from asn1crypto import tsp, cms, util, x509
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class TSPTests(unittest.TestCase):

    def _tsp_fixture(self, eku='time_stamping', critical_eku=True, ca=False,
                    key_usage_present=True, any_eku=False):
        with open(os.path.join(fixtures_dir, 'tsp_request'), 'rb') as f:
            request = tsp.TimeStampReq.load(f.read())
        with open(os.path.join(fixtures_dir, 'tsp_response'), 'rb') as f:
            response = tsp.TimeStampResp.load(f.read())

        signed_data = response['time_stamp_token']['content']
        signer_info = signed_data['signer_infos'][0]
        tst_info = signed_data['encap_content_info']['content'].parsed

        with open(os.path.join(fixtures_dir, 'keys', 'test-der.crt'), 'rb') as f:
            template = x509.Certificate.load(f.read())

        eku_values = ['any_extended_key_usage'] if any_eku else [eku]
        extensions = []
        if key_usage_present:
            extensions.append({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': set(['digital_signature']),
            })
        extensions.append({
            'extn_id': 'extended_key_usage',
            'critical': critical_eku,
            'extn_value': eku_values,
        })
        extensions.append({
            'extn_id': 'basic_constraints',
            'critical': True,
            'extn_value': {'ca': ca},
        })

        tbs_certificate = {
            'version': 'v3',
            'serial_number': signer_info['sid'].chosen['serial_number'].native,
            'signature': {'algorithm': 'sha1_rsa'},
            'issuer': signer_info['sid'].chosen['issuer'],
            'validity': template['tbs_certificate']['validity'],
            'subject': tst_info['tsa'].chosen,
            'subject_public_key_info':
                template['tbs_certificate']['subject_public_key_info'],
            'extensions': extensions,
        }
        certificate = x509.Certificate({
            'tbs_certificate': tbs_certificate,
            'signature_algorithm': {'algorithm': 'sha1_rsa'},
            'signature_value': template['signature_value'].native,
        })
        signed_data['certificates'] = [certificate]

        def signature_verifier(*args, **kwargs):
            return certificate

        return request, response, signed_data, signer_info, tst_info, \
            certificate, signature_verifier

    def _refresh_message_digest(self, signed_data, signer_info):
        digest = hashlib.sha1(
            signed_data['encap_content_info']['content'].contents
        ).digest()
        for attribute in signer_info['signed_attrs']:
            if attribute['type'].native == 'message_digest':
                attribute['values'] = [digest]
            if attribute['type'].native == 'signing_certificate':
                certificate = signed_data['certificates'][0].chosen
                attribute['values'] = [{
                    'certs': [{
                        'cert_hash': hashlib.sha1(certificate.dump()).digest()
                    }]
                }]

    def test_parse_request(self):
        with open(os.path.join(fixtures_dir, 'tsp_request'), 'rb') as f:
            request = tsp.TimeStampReq.load(f.read())

        self.assertEqual(
            'v1',
            request['version'].native
        )
        self.assertEqual(
            'sha1',
            request['message_imprint']['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            request['message_imprint']['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB',
            request['message_imprint']['hashed_message'].native
        )
        self.assertEqual(
            17842879675353045770,
            request['nonce'].native
        )

    def test_parse_response(self):
        with open(os.path.join(fixtures_dir, 'tsp_response'), 'rb') as f:
            response = tsp.TimeStampResp.load(f.read())

        status_info = response['status']
        token = response['time_stamp_token']
        signed_data = token['content']
        encap_content_info = signed_data['encap_content_info']
        tst_info = encap_content_info['content'].parsed
        signer_infos = signed_data['signer_infos']
        signer_info = signer_infos[0]
        signed_attrs = signer_info['signed_attrs']

        self.assertEqual(
            'granted',
            status_info['status'].native
        )
        self.assertEqual(
            None,
            status_info['status_string'].native
        )
        self.assertEqual(
            None,
            status_info['fail_info'].native
        )
        self.assertEqual(
            'signed_data',
            token['content_type'].native
        )
        self.assertIsInstance(
            signed_data,
            cms.SignedData
        )
        self.assertEqual(
            'v3',
            signed_data['version'].native
        )
        self.assertEqual(
            'sha1',
            signed_data['digest_algorithms'][0]['algorithm'].native
        )
        self.assertEqual(
            'tst_info',
            encap_content_info['content_type'].native
        )
        self.assertIsInstance(
            tst_info,
            tsp.TSTInfo
        )
        self.assertEqual(
            'v1',
            tst_info['version'].native
        )
        self.assertEqual(
            '1.1.2',
            tst_info['policy'].native
        )
        self.assertEqual(
            'sha1',
            tst_info['message_imprint']['hash_algorithm']['algorithm'].native
        )
        self.assertEqual(
            None,
            tst_info['message_imprint']['hash_algorithm']['parameters'].native
        )
        self.assertEqual(
            b'\x53\xC9\xDB\xC1\x6D\xDB\x34\x3B\x28\x4E\xEF\xA6\x03\x0E\x02\x64\x79\x31\xAF\xFB',
            tst_info['message_imprint']['hashed_message'].native
        )
        self.assertEqual(
            544918635,
            tst_info['serial_number'].native
        )
        self.assertEqual(
            datetime(2015, 6, 1, 18, 39, 55, tzinfo=util.timezone.utc),
            tst_info['gen_time'].native
        )
        self.assertEqual(
            60,
            tst_info['accuracy']['seconds'].native
        )
        self.assertEqual(
            None,
            tst_info['accuracy']['millis'].native
        )
        self.assertEqual(
            None,
            tst_info['accuracy']['micros'].native
        )
        self.assertEqual(
            False,
            tst_info['ordering'].native
        )
        self.assertEqual(
            17842879675353045770,
            tst_info['nonce'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('organization_name', 'GeoTrust Inc'),
                ('common_name', 'GeoTrust Timestamping Signer 1'),
            ]),
            tst_info['tsa'].native
        )
        self.assertEqual(
            None,
            tst_info['extensions'].native
        )
        self.assertEqual(
            None,
            signed_data['certificates'].native
        )
        self.assertEqual(
            None,
            signed_data['crls'].native
        )
        self.assertEqual(
            1,
            len(signer_infos)
        )
        self.assertEqual(
            'v1',
            signer_info['version'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'issuer',
                    util.OrderedDict([
                        ('country_name', 'ZA'),
                        ('state_or_province_name', 'Western Cape'),
                        ('locality_name', 'Durbanville'),
                        ('organization_name', 'Thawte'),
                        ('organizational_unit_name', 'Thawte Certification'),
                        ('common_name', 'Thawte Timestamping CA'),
                    ])
                ),
                (
                    'serial_number',
                    125680471847352264461591953321128732863
                )
            ]),
            signer_info['sid'].native
        )
        self.assertEqual(
            'sha1',
            signer_info['digest_algorithm']['algorithm'].native
        )
        self.assertEqual(
            4,
            len(signed_attrs)
        )
        self.assertEqual(
            'content_type',
            signed_attrs[0]['type'].native
        )
        self.assertEqual(
            'tst_info',
            signed_attrs[0]['values'][0].native
        )
        self.assertEqual(
            'signing_time',
            signed_attrs[1]['type'].native
        )
        self.assertEqual(
            datetime(2015, 6, 1, 18, 39, 55, tzinfo=util.timezone.utc),
            signed_attrs[1]['values'][0].native
        )
        self.assertEqual(
            'message_digest',
            signed_attrs[2]['type'].native
        )
        self.assertEqual(
            b'\x22\x06\x7D\xA4\xFC\x7B\xC5\x94\x80\xB4\xB0\x78\xC2\x07\x66\x02\xA3\x0D\x62\xAE',
            signed_attrs[2]['values'][0].native
        )
        self.assertEqual(
            'signing_certificate',
            signed_attrs[3]['type'].native
        )
        self.assertEqual(
            util.OrderedDict([
                (
                    'certs',
                    [
                        util.OrderedDict([
                            (
                                'cert_hash',
                                b'\x22\x3C\xDA\x27\x07\x96\x73\x81\x6B\x60\x8A\x1B\x8C\xB0\xAB\x02\x30\x10\x7F\xCC'
                            ),
                            ('issuer_serial', None),
                        ])
                    ]
                ),
                (
                    'policies',
                    None
                )
            ]),
            signed_attrs[3]['values'][0].native
        )

    def test_verify_response_matches_request(self):
        request, response, signed_data, signer_info, tst_info, certificate, \
            signature_verifier = self._tsp_fixture()
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier,
            ['1.1.2']
        )

        self.assertTrue(result.valid)
        self.assertIsNone(result.reason)
        self.assertEqual('granted', result.status)
        self.assertIs(tst_info, result.tst_info)
        self.assertIs(certificate, result.signer_certificate)
        self.assertFalse(result.ordering)
        self.assertFalse(result.local_ordering)
        self.assertEqual(
            (
                datetime(2015, 6, 1, 18, 38, 55, tzinfo=util.timezone.utc),
                datetime(2015, 6, 1, 18, 40, 55, tzinfo=util.timezone.utc),
            ),
            result.time_range
        )

    def test_verify_rejects_message_imprint_digest_despite_callback(self):
        request, response, signed_data, signer_info, tst_info, _, \
            signature_verifier = self._tsp_fixture()
        tst_info['message_imprint']['hashed_message'] = b'A' * 20
        self._refresh_message_digest(signed_data, signer_info)
        calls = []

        def verifier(*args, **kwargs):
            calls.append((args, kwargs))
            return signature_verifier(*args, **kwargs)

        result = response.verify(request, verifier)

        self.assertFalse(result.valid)
        self.assertEqual('message_imprint_mismatch', result.reason)
        self.assertEqual(1, len(calls))

    def test_verify_rejects_message_imprint_algorithm_despite_callback(self):
        request, response, signed_data, signer_info, _, _, \
            signature_verifier = self._tsp_fixture()
        self._refresh_message_digest(signed_data, signer_info)
        request['message_imprint']['hash_algorithm']['algorithm'] = 'sha256'
        calls = []

        def verifier(*args, **kwargs):
            calls.append((args, kwargs))
            return signature_verifier(*args, **kwargs)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('message_imprint_mismatch', result.reason)
        self.assertEqual(1, len(calls))

    def test_verify_rejects_nonce_despite_callback(self):
        request, response, signed_data, signer_info, tst_info, _, \
            signature_verifier = self._tsp_fixture()
        tst_info['nonce'] = request['nonce'].native + 1
        self._refresh_message_digest(signed_data, signer_info)
        calls = []

        def verifier(*args, **kwargs):
            calls.append((args, kwargs))
            return signature_verifier(*args, **kwargs)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('nonce_mismatch', result.reason)
        self.assertEqual(1, len(calls))

    def test_verify_rejects_disallowed_policy(self):
        request, response, signed_data, signer_info, _, _, \
            signature_verifier = self._tsp_fixture()
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier,
            ['1.1.3']
        )

        self.assertFalse(result.valid)
        self.assertEqual('unaccepted_policy', result.reason)

    def test_verify_rejects_policy_not_requested(self):
        request, response, signed_data, signer_info, _, _, \
            signature_verifier = self._tsp_fixture()
        self._refresh_message_digest(signed_data, signer_info)
        request['req_policy'] = '1.1.3'

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('unaccepted_policy', result.reason)

    def test_verify_rejects_non_tsa_certificate_purpose(self):
        request, response, signed_data, signer_info, _, _, \
            signature_verifier = self._tsp_fixture(eku='server_auth')
        self._refresh_message_digest(signed_data, signer_info)
        calls = []

        def verifier(*args, **kwargs):
            calls.append((args, kwargs))
            return signature_verifier(*args, **kwargs)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            'invalid_tsa_certificate_purpose',
            result.reason
        )
        self.assertEqual(1, len(calls))

    def test_verify_rejects_non_critical_tsa_certificate_purpose(self):
        request, response, signed_data, signer_info, _, _, \
            signature_verifier = self._tsp_fixture(critical_eku=False)
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            'invalid_tsa_certificate_purpose',
            result.reason
        )

    def test_verify_rejects_any_extended_key_usage(self):
        request, response, signed_data, signer_info, _, _, \
            signature_verifier = self._tsp_fixture(any_eku=True)
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            'invalid_tsa_certificate_purpose',
            result.reason
        )

    def test_verify_rejects_failed_signature_callback(self):
        request, response, _, _, _, _, _ = self._tsp_fixture()

        result = tsp.verify_time_stamp_response(
            response,
            request,
            lambda *args, **kwargs: False
        )

        self.assertFalse(result.valid)
        self.assertEqual('signature_failed', result.reason)

    def test_verify_rejects_non_certificate_signature_callback_result(self):
        request, response, signed_data, signer_info, _, _, _ = \
            self._tsp_fixture()
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            lambda *args, **kwargs: None
        )

        self.assertFalse(result.valid)
        self.assertEqual('signature_failed', result.reason)

    def test_verify_rejected_status_without_token(self):
        calls = []
        response = tsp.TimeStampResp({
            'status': {
                'status': 'rejection',
                'fail_info': set(['bad_request']),
            }
        })
        with open(os.path.join(fixtures_dir, 'tsp_request'), 'rb') as f:
            request = tsp.TimeStampReq.load(f.read())

        def signature_verifier(*args, **kwargs):
            calls.append((args, kwargs))
            return True

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('pki_status', result.reason)
        self.assertEqual('rejection', result.status)
        self.assertIsNone(result.status_string)
        self.assertEqual(set(['bad_request']), result.fail_info)
        self.assertIsNone(result.tst_info)
        self.assertIsNone(result.time_range)
        self.assertEqual([], calls)

    def test_verify_granted_status_requires_token(self):
        request, _, _, _, _, _, signature_verifier = self._tsp_fixture()
        response = tsp.TimeStampResp({
            'status': {'status': 'granted'}
        })

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('missing_time_stamp_token', result.reason)

    def test_verify_granted_status_rejects_failure_information(self):
        request, _, _, _, _, _, signature_verifier = self._tsp_fixture()
        response = tsp.TimeStampResp({
            'status': {
                'status': 'granted',
                'fail_info': set(['system_failure']),
            }
        })

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('pki_status', result.reason)
        self.assertEqual(set(['system_failure']), result.fail_info)

    def test_verify_ordering_remains_token_local(self):
        request, response, signed_data, signer_info, tst_info, _, \
            signature_verifier = self._tsp_fixture()
        tst_info['ordering'] = True
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertTrue(result.valid)
        self.assertTrue(result.ordering)
        self.assertTrue(result.local_ordering)

    def test_verify_accuracy_milliseconds_and_microseconds_interval(self):
        request, response, signed_data, signer_info, tst_info, _, \
            signature_verifier = self._tsp_fixture()
        tst_info['accuracy'] = {'seconds': 1, 'millis': 2, 'micros': 3}
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertTrue(result.valid)
        self.assertEqual(
            datetime(2015, 6, 1, 18, 39, 53, 997997,
                     tzinfo=util.timezone.utc),
            result.not_before
        )
        self.assertEqual(
            datetime(2015, 6, 1, 18, 39, 56, 2003,
                     tzinfo=util.timezone.utc),
            result.not_after
        )

    def test_verify_rejects_invalid_accuracy(self):
        request, response, signed_data, signer_info, tst_info, _, \
            signature_verifier = self._tsp_fixture()
        tst_info['accuracy'] = {'millis': 1000}
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertFalse(result.valid)
        self.assertEqual('invalid_accuracy', result.reason)

    def test_verify_accepts_missing_tsa_name_using_signer_identity(self):
        request, response, signed_data, signer_info, tst_info, _, \
            signature_verifier = self._tsp_fixture()
        del tst_info['tsa']
        self._refresh_message_digest(signed_data, signer_info)

        result = tsp.verify_time_stamp_response(
            response,
            request,
            signature_verifier
        )

        self.assertTrue(result.valid)
        self.assertIsNone(result.tst_info['tsa'].native)
