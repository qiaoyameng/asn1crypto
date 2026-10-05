# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
from datetime import datetime

from asn1crypto import tsp, cms, util, x509
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class RecordingCallback(object):
    """
    Stand-in for a caller-provided signature/certificate-chain verifier.
    Records the arguments it was called with and either succeeds or raises to
    simulate a failed cryptographic check.
    """

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, signer_certificate, signed_data, signer_info,
                 tst_info, response):
        self.calls.append({
            'signer_certificate': signer_certificate,
            'signed_data': signed_data,
            'signer_info': signer_info,
            'tst_info': tst_info,
            'response': response,
        })
        if self.fail:
            raise ValueError('signature invalid')


class TSPTests(unittest.TestCase):

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


class TSPVerificationTests(unittest.TestCase):

    def _fixture(self, name):
        with open(os.path.join(fixtures_dir, name), 'rb') as f:
            return f.read()

    def setUp(self):
        self.request_der = self._fixture('tsp_verify_request')
        self.request = tsp.TimeStampReq.load(self.request_der)
        self.valid_der = self._fixture('tsp_verify_response.der')
        self.callback = RecordingCallback()

    def test_valid_response_verifies_and_invokes_callback(self):
        result = tsp.verify_tsp_response(
            self.valid_der, self.request_der, self.callback
        )

        self.assertIsInstance(result, tsp.VerifiedTimeStamp)
        self.assertEqual(1, len(self.callback.calls))
        call = self.callback.calls[0]
        self.assertIsInstance(call['signer_certificate'], x509.Certificate)
        self.assertEqual(
            result.signer_certificate,
            call['signer_certificate']
        )
        self.assertIsInstance(call['signed_data'], cms.SignedData)
        self.assertIsInstance(call['signer_info'], cms.SignerInfo)
        self.assertIsInstance(call['tst_info'], tsp.TSTInfo)
        self.assertIsInstance(call['response'], tsp.TimeStampResp)

        self.assertEqual(
            datetime(2025, 6, 1, 12, 0, 0, tzinfo=util.timezone.utc),
            result.gen_time
        )
        # 5 seconds + 250 millis + 100 micros
        self.assertEqual(5.2501, result.accuracy_seconds)
        self.assertEqual(
            datetime(2025, 6, 1, 11, 59, 54, 749900, tzinfo=util.timezone.utc),
            result.gen_time_lower
        )
        self.assertEqual(
            datetime(2025, 6, 1, 12, 0, 5, 250100, tzinfo=util.timezone.utc),
            result.gen_time_upper
        )
        self.assertTrue(result.ordering)
        self.assertEqual('1.2.3.4.5', result.policy)
        self.assertEqual(12345, result.serial_number)
        self.assertEqual(
            self.request['message_imprint']['hashed_message'].native,
            result.message_imprint['hashed_message'].native
        )

    def test_accepts_parsed_objects(self):
        response = tsp.TimeStampResp.load(self.valid_der)
        result = tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertIsInstance(result, tsp.VerifiedTimeStamp)
        self.assertEqual(1, len(self.callback.calls))

    def test_message_digest_substitution_rejected_even_if_signature_passes(self):
        data = self._fixture('tsp_verify_response_bad_digest.der')
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(data, self.request_der, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_message_imprint_digest,
            ctx.exception.reason
        )
        # The signature callback must never run for a non-corresponding token
        self.assertEqual(0, len(self.callback.calls))

    def test_message_imprint_algorithm_substitution_rejected(self):
        altered_request = tsp.TimeStampReq.load(self.request_der)
        altered_request['message_imprint']['hash_algorithm']['algorithm'] = 'sha1'
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(self.valid_der, altered_request, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_message_imprint_algorithm,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_nonce_substitution_rejected_even_if_signature_passes(self):
        data = self._fixture('tsp_verify_response_bad_nonce.der')
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(data, self.request_der, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.nonce_mismatch,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_tsa_purpose_substitution_rejected_even_if_signature_passes(self):
        data = self._fixture('tsp_verify_response_bad_tsa_purpose.der')
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(data, self.request_der, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_tsa_certificate_purpose,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_policy_not_accepted_rejected(self):
        data = self._fixture('tsp_verify_response_bad_policy.der')
        # The request pins 1.2.3.4.5 via reqPolicy, so the substituted policy
        # is rejected without consulting the callback
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(data, self.request_der, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_policy,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_explicit_acceptable_policies_filter(self):
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(
                self.valid_der, self.request_der, self.callback,
                acceptable_policies=['1.9.9.9']
            )
        self.assertEqual(
            tsp.TSPVerificationError.invalid_policy,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

        result = tsp.verify_tsp_response(
            self.valid_der, self.request_der, self.callback,
            acceptable_policies=['1.2.3.4.5', '1.9.9.9']
        )
        self.assertIsInstance(result, tsp.VerifiedTimeStamp)
        self.assertEqual(1, len(self.callback.calls))

    def test_rejection_response_returns_rejection_reason(self):
        data = self._fixture('tsp_verify_rejection.der')
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(data, self.request_der, self.callback)
        error = ctx.exception
        self.assertEqual(tsp.TSPVerificationError.bad_status, error.reason)
        self.assertEqual('rejection', error.pki_status)
        self.assertEqual({'bad_request'}, error.pki_failure_info)
        # No token means no success-like empty result, and the callback must
        # never run
        self.assertEqual(0, len(self.callback.calls))

    def test_callback_failure_rejected(self):
        failing = RecordingCallback(fail=True)
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(self.valid_der, self.request_der, failing)
        self.assertEqual(
            tsp.TSPVerificationError.signature_invalid,
            ctx.exception.reason
        )
        self.assertEqual(1, len(failing.calls))

    def test_granted_without_token_does_not_return_success(self):
        status = tsp.PKIStatusInfo({'status': 'granted'})
        response = tsp.TimeStampResp({'status': status})
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(tsp.TSPVerificationError.no_token, ctx.exception.reason)
        self.assertEqual(0, len(self.callback.calls))

    def test_request_without_nonce_allows_token_without_nonce(self):
        imprint = self.request['message_imprint']
        request = tsp.TimeStampReq({
            'version': 'v1',
            'message_imprint': imprint,
            'cert_req': True,
        })
        # Strip the response nonce by rebuilding the TSTInfo inside the token
        response = self._response_without_nonce()
        result = tsp.verify_tsp_response(response, request, self.callback)
        self.assertIsInstance(result, tsp.VerifiedTimeStamp)

    def test_request_nonce_must_be_echoed(self):
        imprint = self.request['message_imprint']
        request = tsp.TimeStampReq({
            'version': 'v1',
            'message_imprint': imprint,
            'nonce': 4242,
            'cert_req': True,
        })
        response = self._response_without_nonce()
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, request, self.callback)
        self.assertEqual(tsp.TSPVerificationError.nonce_mismatch, ctx.exception.reason)

    def test_tsa_name_must_match_signer_subject(self):
        response = self._response_with_wrong_tsa_name()
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_tsa_name,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_message_digest_attribute_must_match_econtent(self):
        response = self._response_with_bad_message_digest_attr()
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_signed_attributes,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_ess_cert_id_must_match_signer(self):
        response = self._response_with_wrong_ess_cert_id()
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.invalid_ess_cert_id,
            ctx.exception.reason
        )
        self.assertEqual(0, len(self.callback.calls))

    def test_accuracy_without_accuracy_field_is_zero_interval(self):
        response = self._response_without_accuracy()
        result = tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(0.0, result.accuracy_seconds)
        self.assertEqual(result.gen_time, result.gen_time_lower)
        self.assertEqual(result.gen_time, result.gen_time_upper)
        self.assertFalse(result.ordering)

    def test_invalid_accuracy_rejected(self):
        response, certificate, signer_name = self._valid_parts()
        tst_info = response['time_stamp_token']['content']['encap_content_info'][
            'content'].parsed
        new_tst = tsp.TSTInfo({
            'version': tst_info['version'],
            'policy': tst_info['policy'].dotted,
            'message_imprint': tst_info['message_imprint'],
            'serial_number': tst_info['serial_number'].native,
            'gen_time': tst_info['gen_time'].native,
            'accuracy': tsp.Accuracy({'seconds': -5}),
            'ordering': tst_info['ordering'].native,
            'nonce': tst_info['nonce'].native,
            'tsa': tst_info['tsa'],
        })
        rebuilt = self._rebuild_token(new_tst, certificate, signer_name)
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(rebuilt, self.request, self.callback)
        self.assertEqual(tsp.TSPVerificationError.invalid_accuracy, ctx.exception.reason)

    def test_malformed_response_bytes_rejected(self):
        for data in (b'garbage', b'\x30\x00'):
            with self.assertRaises(tsp.TSPVerificationError) as ctx:
                tsp.verify_tsp_response(data, self.request_der, self.callback)
            self.assertEqual(tsp.TSPVerificationError.malformed, ctx.exception.reason)
            self.assertEqual(0, len(self.callback.calls))

    def test_granted_with_mods_is_accepted(self):
        response = tsp.TimeStampResp.load(self.valid_der)
        response['status']['status'] = 'granted_with_mods'
        result = tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertIsInstance(result, tsp.VerifiedTimeStamp)

    def test_waiting_status_is_a_rejection_reason(self):
        response = tsp.TimeStampResp({
            'status': tsp.PKIStatusInfo({'status': 'waiting'})
        })
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(tsp.TSPVerificationError.bad_status, ctx.exception.reason)
        self.assertEqual('waiting', ctx.exception.pki_status)
        self.assertEqual(0, len(self.callback.calls))

    def test_non_signed_data_token_rejected(self):
        response = tsp.TimeStampResp({
            'status': tsp.PKIStatusInfo({'status': 'granted'}),
            'time_stamp_token': cms.ContentInfo({
                'content_type': 'data',
                'content': b'',
            }),
        })
        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(tsp.TSPVerificationError.invalid_token, ctx.exception.reason)
        self.assertEqual(0, len(self.callback.calls))

    def test_signer_certificate_supplied_outside_token(self):
        response = tsp.TimeStampResp.load(self.valid_der)
        embedded = response['time_stamp_token']['content']['certificates']
        signer_certificate = embedded[0].chosen.dump()
        del response['time_stamp_token']['content']['certificates']

        with self.assertRaises(tsp.TSPVerificationError) as ctx:
            tsp.verify_tsp_response(response, self.request, self.callback)
        self.assertEqual(
            tsp.TSPVerificationError.signer_certificate_missing,
            ctx.exception.reason
        )

        fresh = tsp.TimeStampResp.load(self.valid_der)
        del fresh['time_stamp_token']['content']['certificates']
        result = tsp.verify_tsp_response(
            fresh, self.request, self.callback,
            signer_certificate=signer_certificate
        )
        self.assertIsInstance(result, tsp.VerifiedTimeStamp)
        self.assertEqual(
            signer_certificate,
            self.callback.calls[0]['signer_certificate'].dump()
        )

    def _rebuild_token(self, tst_info, signer_certificate, signer_name,
                       message_digest_override=None, cert_hash_override=None):
        import hashlib
        from asn1crypto.core import ParsableOctetString

        econtent = tst_info.dump()
        calculated = hashlib.sha256(econtent).digest()
        if message_digest_override is not None:
            calculated = message_digest_override
        cert_hash = hashlib.sha256(signer_certificate.dump()).digest()
        if cert_hash_override is not None:
            cert_hash = cert_hash_override

        signed_attrs = cms.CMSAttributes([
            cms.CMSAttribute({
                'type': 'content_type',
                'values': [cms.ContentType('tst_info')],
            }),
            cms.CMSAttribute({
                'type': 'signing_time',
                'values': [cms.Time({'utc_time': '250601120000Z'})],
            }),
            cms.CMSAttribute({
                'type': 'message_digest',
                'values': [calculated],
            }),
            cms.CMSAttribute({
                'type': 'signing_certificate_v2',
                'values': [tsp.SigningCertificateV2({
                    'certs': [tsp.ESSCertIDv2({
                        'hash_algorithm': {'algorithm': 'sha256'},
                        'cert_hash': cert_hash,
                    })],
                })],
            }),
        ])
        signer_info = cms.SignerInfo({
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': {
                    'issuer': signer_name,
                    'serial_number': signer_certificate.serial_number,
                },
            }),
            'digest_algorithm': {'algorithm': 'sha256'},
            'signed_attrs': signed_attrs,
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature': b'\x00' * 64,
        })
        signed_data = cms.SignedData({
            'version': 'v3',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'encap_content_info': cms.EncapsulatedContentInfo({
                'content_type': 'tst_info',
                'content': ParsableOctetString(econtent),
            }),
            'certificates': [signer_certificate],
            'signer_infos': [signer_info],
        })
        return tsp.TimeStampResp({
            'status': tsp.PKIStatusInfo({'status': 'granted'}),
            'time_stamp_token': cms.ContentInfo({
                'content_type': 'signed_data',
                'content': signed_data,
            }),
        })

    def _valid_parts(self):
        response = tsp.TimeStampResp.load(self.valid_der)
        signed_data = response['time_stamp_token']['content']
        certificate = signed_data['certificates'][0].chosen
        signer_name = certificate.subject
        return response, certificate, signer_name

    def _response_without_nonce(self):
        response, certificate, signer_name = self._valid_parts()
        tst_info = response['time_stamp_token']['content']['encap_content_info'][
            'content'].parsed
        new_tst = tsp.TSTInfo({
            'version': tst_info['version'],
            'policy': tst_info['policy'].dotted,
            'message_imprint': tst_info['message_imprint'],
            'serial_number': tst_info['serial_number'].native,
            'gen_time': tst_info['gen_time'].native,
            'accuracy': tst_info['accuracy'].native if tst_info['accuracy'] is not None else None,
            'ordering': tst_info['ordering'].native,
            'tsa': tst_info['tsa'],
        })
        return self._rebuild_token(new_tst, certificate, signer_name)

    def _response_with_wrong_tsa_name(self):
        response, certificate, _ = self._valid_parts()
        tst_info = response['time_stamp_token']['content']['encap_content_info'][
            'content'].parsed
        new_tst = tsp.TSTInfo({
            'version': tst_info['version'],
            'policy': tst_info['policy'].dotted,
            'message_imprint': tst_info['message_imprint'],
            'serial_number': tst_info['serial_number'].native,
            'gen_time': tst_info['gen_time'].native,
            'accuracy': tst_info['accuracy'].native,
            'ordering': tst_info['ordering'].native,
            'nonce': tst_info['nonce'].native,
            'tsa': x509.GeneralName({
                'directory_name': x509.Name.build({'common_name': 'Some Other TSA'})
            }),
        })
        # The signer subject stays the real one; only TSTInfo.tsa lies
        return self._rebuild_token(new_tst, certificate, certificate.subject)

    def _response_with_bad_message_digest_attr(self):
        response, certificate, signer_name = self._valid_parts()
        tst_info = response['time_stamp_token']['content']['encap_content_info'][
            'content'].parsed
        return self._rebuild_token(
            tst_info, certificate, signer_name,
            message_digest_override=b'\xff' * 32
        )

    def _response_with_wrong_ess_cert_id(self):
        response, certificate, signer_name = self._valid_parts()
        tst_info = response['time_stamp_token']['content']['encap_content_info'][
            'content'].parsed
        return self._rebuild_token(
            tst_info, certificate, signer_name,
            cert_hash_override=b'\xee' * 32
        )

    def _response_without_accuracy(self):
        response, certificate, signer_name = self._valid_parts()
        tst_info = response['time_stamp_token']['content']['encap_content_info'][
            'content'].parsed
        new_tst = tsp.TSTInfo({
            'version': tst_info['version'],
            'policy': tst_info['policy'].dotted,
            'message_imprint': tst_info['message_imprint'],
            'serial_number': tst_info['serial_number'].native,
            'gen_time': tst_info['gen_time'].native,
            'ordering': False,
            'nonce': tst_info['nonce'].native,
            'tsa': tst_info['tsa'],
        })
        return self._rebuild_token(new_tst, certificate, signer_name)
