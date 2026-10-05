# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
import hashlib

from asn1crypto import algos, core, csr, keys, util, x509
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
    num_cls = long  # noqa
else:
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CSRTests(unittest.TestCase):

    def _rsa_key(self):
        with open(os.path.join(fixtures_dir, 'keys/test-der.key'), 'rb') as f:
            return keys.RSAPrivateKey.load(f.read())

    def _extension(self, extn_id, value, critical=False):
        extension = x509.Extension()
        extension['extn_id'] = extn_id
        extension['critical'] = critical
        extension['extn_value'] = core.ParsableOctetString(value.dump())
        return extension

    def _extension_request_attribute(self, extensions):
        attribute = csr.CRIAttribute()
        attribute['type'] = 'extension_request'
        attribute['values'] = [x509.Extensions(extensions)]
        return attribute

    def _unknown_extension(self, critical):
        extension = x509.Extension()
        extension['extn_id'] = x509.ExtensionId('1.2.3.4.5.6.7')
        extension['critical'] = critical
        extension['extn_value'] = core.ParsableOctetString(b'\x04\x00')
        return extension

    def _subject_alt_name_extension(self, dns_name):
        general_names = x509.GeneralNames([
            x509.GeneralName(
                name='dns_name',
                value=x509.DNSName(dns_name)
            )
        ])
        return self._extension('subject_alt_name', general_names)

    def _signed_certification_request(self, subject, attributes, private_key):
        public_key = keys.RSAPublicKey()
        public_key['modulus'] = private_key['modulus']
        public_key['public_exponent'] = private_key['public_exponent']

        request_info = csr.CertificationRequestInfo()
        request_info['version'] = 0
        request_info['subject'] = x509.Name.build({'common_name': subject})
        request_info['subject_pk_info'] = keys.PublicKeyInfo.wrap(public_key, 'rsa')
        request_info['attributes'] = attributes

        request_info_bytes = request_info.dump()
        digest_info_prefix = (
            b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
            b'\x05\x00\x04\x20'
        )
        digest = hashlib.sha256(request_info_bytes).digest()
        encoded_message = (
            b'\x00\x01' +
            (b'\xff' * (256 - len(digest_info_prefix + digest) - 3)) +
            b'\x00' +
            digest_info_prefix + digest
        )
        signature_int = pow(
            util.int_from_bytes(encoded_message),
            private_key['private_exponent'].native,
            private_key['modulus'].native
        )

        request = csr.CertificationRequest()
        request['certification_request_info'] = request_info
        request['signature_algorithm'] = algos.SignedDigestAlgorithm({
            'algorithm': 'sha256_rsa'
        })
        request['signature'] = util.int_to_bytes(signature_int, width=256)
        return request.dump(), request_info_bytes

    def _verify_rsa_sha256(
            self,
            request_info,
            signature_algorithm,
            signature,
            subject_pk_info):
        self.assertEqual(
            'sha256_rsa',
            signature_algorithm['algorithm'].native
        )

        public_key = subject_pk_info['public_key'].parsed
        em = util.int_to_bytes(
            pow(
                util.int_from_bytes(signature),
                public_key['public_exponent'].native,
                public_key['modulus'].native
            ),
            width=256
        )

        digest_info_prefix = (
            b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
            b'\x05\x00\x04\x20'
        )
        digest = hashlib.sha256(request_info).digest()
        padding = (
            b'\x00\x01' +
            (b'\xff' * (256 - len(digest_info_prefix + digest) - 3)) +
            b'\x00'
        )
        return em == padding + digest_info_prefix + digest

    def test_parse_csr(self):
        with open(os.path.join(fixtures_dir, 'test-inter-der.csr'), 'rb') as f:
            certification_request = csr.CertificationRequest.load(f.read())

        cri = certification_request['certification_request_info']

        self.assertEqual(
            'v1',
            cri['version'].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing Intermediate'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            cri['subject'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsa'),
                ('parameters', None),
            ]),
            cri['subject_pk_info']['algorithm'].native
        )
        self.assertEqual(
            24141757533938720807477509823483015516687050697622322097001928034085434547050399731881871694642845241206788286795830006142635608141713689209738431462004600429798152826994774062467402648660593454536565119527837471261495586474194846971065722669734666949739228862107500673350843489920495869942508240779131331715037662761414997889327943217889802893638175792326783316531272170879284118280173511200768884738639370318760377047837471530387161553030663446359575963736475504659902898072137674205021477968813148345198711103071746476009234601299344030395455052526948041544669303473529511160643491569274897838845918784633403435929,  # noqa
            cri['subject_pk_info']['public_key'].parsed['modulus'].native
        )
        self.assertEqual(
            65537,
            cri['subject_pk_info']['public_key'].parsed['public_exponent'].native
        )
        self.assertEqual(
            [],
            cri['attributes'].native
        )

    def test_evaluate_rejects_overreaching_ca_after_signature_verification(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = True
        extension = self._extension(
            'basic_constraints',
            basic_constraints,
            critical=True
        )
        attribute = self._extension_request_attribute([extension])
        request, request_info = self._signed_certification_request(
            'ca.example',
            [attribute],
            private_key
        )

        calls = []

        def verify(request_info_bytes, signature_algorithm, signature, subject_pk_info):
            calls.append((
                request_info_bytes,
                signature_algorithm,
                signature,
                subject_pk_info
            ))
            return self._verify_rsa_sha256(
                request_info_bytes,
                signature_algorithm,
                signature,
                subject_pk_info
            )

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                verify,
                ['basic_constraints']
            )

        self.assertEqual(1, len(calls))
        self.assertEqual(request_info, calls[0][0])
        self.assertEqual(
            'sha256_rsa',
            calls[0][1]['algorithm'].native
        )
        self.assertIsInstance(calls[0][2], byte_cls)
        self.assertEqual(
            'rsa',
            calls[0][3]['algorithm']['algorithm'].native
        )
        self.assertEqual(
            'Request for CA basic constraints is not allowed',
            cm.exception.args[0]
        )
        error_message = cm.exception.args[0].encode('utf-8')
        self.assertNotIn(private_key.dump(), error_message)
        self.assertNotIn(request, error_message)

    def test_evaluate_rejects_duplicate_extension_requests_after_signature_verification(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = False
        extension = self._extension('basic_constraints', basic_constraints)
        attributes = [
            self._extension_request_attribute([extension]),
            self._extension_request_attribute([extension]),
        ]
        request, request_info = self._signed_certification_request(
            'duplicate.example',
            attributes,
            private_key
        )

        calls = []

        def verify(request_info_bytes, signature_algorithm, signature, subject_pk_info):
            calls.append((
                request_info_bytes,
                signature_algorithm,
                signature,
                subject_pk_info
            ))
            return self._verify_rsa_sha256(
                request_info_bytes,
                signature_algorithm,
                signature,
                subject_pk_info
            )

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                verify,
                ['basic_constraints']
            )

        self.assertEqual(1, len(calls))
        self.assertEqual(request_info, calls[0][0])
        self.assertEqual(
            'Duplicate extensionRequest attribute is not allowed',
            cm.exception.args[0]
        )
        error_message = cm.exception.args[0].encode('utf-8')
        self.assertNotIn(private_key.dump(), error_message)
        self.assertNotIn(request, error_message)

    def test_evaluate_rejects_invalid_signature_before_extension_policy(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = True
        extension = self._extension(
            'basic_constraints',
            basic_constraints,
            critical=True
        )
        attribute = self._extension_request_attribute([extension])
        request, _ = self._signed_certification_request(
            'invalid.example',
            [attribute],
            private_key
        )

        def verify(request_info_bytes, signature_algorithm, signature, subject_pk_info):
            return False

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                verify,
                []
            )

        self.assertEqual(
            'CSR signature verification failed',
            cm.exception.args[0]
        )
        self.assertTrue(cm.exception.__suppress_context__)

    def test_evaluate_sanitizes_verification_callback_exception(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = True
        extension = self._extension(
            'basic_constraints',
            basic_constraints,
            critical=True
        )
        attribute = self._extension_request_attribute([extension])
        request, _ = self._signed_certification_request(
            'callback-error.example',
            [attribute],
            private_key
        )

        def verify(request_info_bytes, signature_algorithm, signature, subject_pk_info):
            raise RuntimeError(request_info_bytes)

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                verify,
                []
            )

        self.assertEqual(
            'CSR signature verification failed',
            cm.exception.args[0]
        )
        self.assertIsNone(cm.exception.__cause__)
        self.assertTrue(cm.exception.__suppress_context__)

    def test_evaluate_returns_candidate_extensions_with_sources(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = False
        key_usage = x509.KeyUsage(set([
            'digital_signature',
            'key_encipherment'
        ]))
        extensions = [
            self._extension('basic_constraints', basic_constraints),
            self._extension('key_usage', key_usage, critical=True),
        ]
        attribute = self._extension_request_attribute(extensions)
        request, _ = self._signed_certification_request(
            'valid.example',
            [attribute],
            private_key
        )

        result = csr.evaluate_certification_request(
            request,
            self._verify_rsa_sha256,
            ['2.5.29.19', 'key_usage']
        )

        self.assertEqual(
            ['basic_constraints', 'key_usage'],
            [
                candidate.extension['extn_id'].native
                for candidate in result.extension_candidates
            ]
        )
        self.assertEqual(
            {
                'attribute_index': 0,
                'attribute_occurrence': 1,
                'extension_index': 1,
            },
            result.extension_candidates[1].source
        )
        self.assertFalse(hasattr(result, 'certificate'))

    def test_evaluate_rejects_unknown_critical_extension(self):
        private_key = self._rsa_key()
        attribute = self._extension_request_attribute([
            self._unknown_extension(True)
        ])
        request, _ = self._signed_certification_request(
            'unknown-critical.example',
            [attribute],
            private_key
        )

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                self._verify_rsa_sha256,
                ['1.2.3.4.5.6.7']
            )

        self.assertEqual(
            'Unknown critical extension is not allowed: 1.2.3.4.5.6.7',
            cm.exception.args[0]
        )

        result = csr.evaluate_certification_request(
            request,
            self._verify_rsa_sha256,
            ['1.2.3.4.5.6.7'],
            allow_unknown_critical=True
        )
        self.assertEqual(1, len(result.extension_candidates))

    def test_evaluate_rejects_duplicate_extension_oid(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = False
        extension = self._extension('basic_constraints', basic_constraints)
        attribute = self._extension_request_attribute([
            extension,
            extension
        ])
        request, _ = self._signed_certification_request(
            'duplicate-extension.example',
            [attribute],
            private_key
        )

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                self._verify_rsa_sha256,
                ['basic_constraints']
            )

        self.assertEqual(
            'Duplicate extension OID in extension request: 2.5.29.19',
            cm.exception.args[0]
        )

    def test_evaluate_rejects_conflicting_duplicate_subject_alt_names(self):
        private_key = self._rsa_key()
        attribute = self._extension_request_attribute([
            self._subject_alt_name_extension('a.example'),
            self._subject_alt_name_extension('b.example')
        ])
        request, _ = self._signed_certification_request(
            'conflicting-san.example',
            [attribute],
            private_key
        )

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                self._verify_rsa_sha256,
                ['subject_alt_name']
            )

        self.assertEqual(
            'Duplicate extension OID in extension request: 2.5.29.17',
            cm.exception.args[0]
        )

    def test_evaluate_rejects_conflicting_basic_constraints_and_key_usage(self):
        private_key = self._rsa_key()
        basic_constraints = x509.BasicConstraints()
        basic_constraints['ca'] = False
        key_usage = x509.KeyUsage(set([
            'digital_signature',
            'key_cert_sign'
        ]))
        extensions = [
            self._extension('basic_constraints', basic_constraints),
            self._extension('key_usage', key_usage, critical=True),
        ]
        attribute = self._extension_request_attribute(extensions)
        request, _ = self._signed_certification_request(
            'conflict.example',
            [attribute],
            private_key
        )

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(
                request,
                self._verify_rsa_sha256,
                ['basic_constraints', 'key_usage'],
                allow_ca=True
            )

        self.assertEqual(
            'CA key usage conflicts with non-CA basic constraints',
            cm.exception.args[0]
        )

    def test_parse_csr2(self):
        with open(os.path.join(fixtures_dir, 'test-third-der.csr'), 'rb') as f:
            certification_request = csr.CertificationRequest.load(f.read())

        cri = certification_request['certification_request_info']

        self.assertEqual(
            'v1',
            cri['version'].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Test Third-Level Certificate'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            cri['subject'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsa'),
                ('parameters', None),
            ]),
            cri['subject_pk_info']['algorithm'].native
        )
        self.assertEqual(
            24242772097421005542208203320016703216069397492249392798445262959177221203301502279838173203064357049006693856302147277901773700963054800321566171864477088538775137040886151390015408166478059887940234405152693144166884492162723776487601158833605063151869850475289834250129252480954724818505034734280077580919995584375189497366089269712298471489896645221362055822887892887126082288043106492130176555423739906252380437817155678204772878611148787130925042126257401487070141904017757131876614711613405231164930930771261221451019736883391322299033324412671768599041417705072563016759224152503535867541947310239343903761461,  # noqa
            cri['subject_pk_info']['public_key'].parsed['modulus'].native
        )
        self.assertEqual(
            65537,
            cri['subject_pk_info']['public_key'].parsed['public_exponent'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('type', 'extension_request'),
                    (
                        'values',
                        [
                            [
                                util.OrderedDict([
                                    ('extn_id', 'basic_constraints'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        util.OrderedDict([
                                            ('ca', False),
                                            ('path_len_constraint', None),
                                        ])
                                    ),
                                ]),
                                util.OrderedDict([
                                    ('extn_id', 'key_usage'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        set(['digital_signature', 'non_repudiation', 'key_encipherment']),
                                    ),
                                ])
                            ]
                        ]
                    ),
                ]),
            ],
            cri['attributes'].native
        )

    def test_parse_csr3(self):
        with open(os.path.join(fixtures_dir, 'test-windows-host.csr'), 'rb') as f:
            certification_request = csr.CertificationRequest.load(f.read())

        cri = certification_request['certification_request_info']

        self.assertEqual(
            'v1',
            cri['version'].native
        )

        self.assertEqual(
            util.OrderedDict([
                ('common_name', 'windows.host.example.net'),
            ]),
            cri['subject'].native
        )
        self.assertEqual(
            util.OrderedDict([
                ('algorithm', 'rsa'),
                ('parameters', None),
            ]),
            cri['subject_pk_info']['algorithm'].native
        )
        self.assertEqual(
            0x00bd5b280774e2e64a2c022abd50de7817aaec50367e94b9c6459ca876daaf3bc3d7ffc41bf902422ac9af7d369eeb23245c5d8e2dda5434463f1d3e596c066a3cbe936bd89b4b7b9923ff6e654608cd3aa1fbc36543165752dde12c889c7aee4b5423e311e507bfd9fa60166290ae766005209120b651c3cdeceabba90b115341d656cb1fe94f372ba7c170bd15261685e92303205a7e5141928415f748d77ee4c6ecf8749b80c07d99f99f9aff629be62840e43e4696d6602df2a7a5e1bf11925021f2df2f4d27ef42e4decb0dc615c29eecaca628721a0c3c70c2700b7c658d6b7b7b6285593fd7d5ae086447bdc30429c7231db6b831d44e4c019887542f5f,  # noqa
            cri['subject_pk_info']['public_key'].parsed['modulus'].native
        )
        self.assertEqual(
            65537,
            cri['subject_pk_info']['public_key'].parsed['public_exponent'].native
        )
        self.assertEqual(
            [
                util.OrderedDict([
                    ('type', 'microsoft_os_version'),
                    ('values', ['6.2.9200.2']),
                ]),
                util.OrderedDict([
                    ('type', 'microsoft_request_client_info'),
                    (
                        'values',
                        [
                            util.OrderedDict([
                                ('clientid', 5),
                                ('machinename', 'windows.host.example.net'),
                                ('username', 'locuser'),
                                ('processname', 'MMC.EXE'),
                            ])
                        ])
                    ]
                ),
                util.OrderedDict([
                    ('type', 'microsoft_enrollment_csp_provider'),
                    (
                        'values',
                        [
                            util.OrderedDict([
                                ('keyspec', 1),
                                ('cspname', 'Microsoft RSA SChannel Cryptographic Provider'),
                                ('signature', ()),
                            ])
                        ]
                    ),
                ]),
                util.OrderedDict([
                    ('type', 'extension_request'),
                    (
                        'values',
                        [
                            [
                                util.OrderedDict([
                                    ('extn_id', 'microsoft_enroll_certtype'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        'Machine',
                                    )
                                ]),
                                util.OrderedDict([
                                    ('extn_id', 'extended_key_usage'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        ['client_auth', 'server_auth'],
                                    ),
                                ]),
                                util.OrderedDict([
                                    ('extn_id', 'key_usage'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        set(['digital_signature', 'key_encipherment']),
                                    ),
                                ]),
                                util.OrderedDict([
                                    ('extn_id', 'key_identifier'),
                                    ('critical', False),
                                    (
                                        'extn_value',
                                        bytearray.fromhex('2a 98 4b c1 ff 6e 16 ed 2d 69 35 0a 26 e7 1f 8c 05 4f b8 e6'),  # noqa
                                    ),
                                ]),
                            ]
                        ]
                    ),
                ]),
            ],
            cri['attributes'].native
        )
