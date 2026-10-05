# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import unittest
import sys
import os

from asn1crypto import algos, csr, keys, util, x509
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


# A static 1024-bit RSA key pair used only by these tests to produce CSRs
# with verifiable signatures without requiring a crypto library.
_TEST_RSA_N = 151849606045680612989746556309638398717477723759051839918442825203961369414414499091920115651981722594077834216037391113450469664323410763416578982702053578347473160171257091825153807275057984219383617284123741766409170179863002846698472138872429360177939524580055389986404399689127347330675404427720647415923  # noqa
_TEST_RSA_E = 65537
_TEST_RSA_D = 129242580911974374667257624104729082510046346815995721968517643314112107449777084079944215497620282989725828044777235398450756029051678477552783552117438198658606923276647801490423197788793034681151167457375897215731167099056196244500483756671729533645428682214329191430780811204840719171476054801373231367393  # noqa

_SHA256_DIGEST_INFO_PREFIX = bytearray.fromhex('30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20')  # noqa


def _rsa_pkcs1_em(cri_bytes):
    digest_info = _SHA256_DIGEST_INFO_PREFIX + bytearray(hashlib.sha256(cri_bytes).digest())
    key_bytes = (_TEST_RSA_N.bit_length() + 7) // 8
    padding = bytearray(b'\xff') * (key_bytes - len(digest_info) - 3)
    return b'\x00\x01' + bytes(padding) + b'\x00' + bytes(digest_info)


def _rsa_sign(cri_bytes):
    sig_int = pow(util.int_from_bytes(_rsa_pkcs1_em(cri_bytes)), _TEST_RSA_D, _TEST_RSA_N)
    return util.int_to_bytes(sig_int, width=(_TEST_RSA_N.bit_length() + 7) // 8)


def _rsa_verify(cri_bytes, signature):
    sig_int = util.int_from_bytes(signature)
    em = util.int_to_bytes(pow(sig_int, _TEST_RSA_E, _TEST_RSA_N), width=(_TEST_RSA_N.bit_length() + 7) // 8)
    return em == _rsa_pkcs1_em(cri_bytes)


def _test_public_key_info():
    return keys.PublicKeyInfo({
        'algorithm': {'algorithm': 'rsa'},
        'public_key': keys.RSAPublicKey({
            'modulus': _TEST_RSA_N,
            'public_exponent': _TEST_RSA_E,
        }),
    })


def _extension_request_attribute(extensions):
    attribute = csr.CRIAttribute()
    attribute['type'] = 'extension_request'
    attribute['values'] = csr.SetOfExtensions([x509.Extensions(extensions)])
    return attribute


def _build_csr(extension_requests, tamper_signature=False):
    cri = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': x509.Name.build({'common_name': 'eval-test.example'}),
        'subject_pk_info': _test_public_key_info(),
        'attributes': csr.CRIAttributes([
            _extension_request_attribute(extensions)
            for extensions in extension_requests
        ]),
    })
    signature = _rsa_sign(cri.dump())
    if tamper_signature:
        signature = signature[:-1] + bytes(bytearray([signature[-1] ^ 0x01]))
    return csr.CertificationRequest({
        'certification_request_info': cri,
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'signature': signature,
    })


def _verifying_callback(cri_bytes, signature_algorithm, signature):
    if signature_algorithm['algorithm'].native != 'sha256_rsa':
        return False
    return _rsa_verify(cri_bytes, signature)


class CSREvaluationTests(unittest.TestCase):

    def _leaf_policy(self, **kwargs):
        return csr.CSREvaluationPolicy(
            allowed_extensions=['subject_alt_name', 'key_usage', 'basic_constraints'],
            **kwargs
        )

    def test_evaluate_valid_request(self):
        request = _build_csr([[
            x509.Extension({
                'extn_id': 'subject_alt_name',
                'extn_value': x509.GeneralNames([x509.GeneralName('dns_name', 'eval-test.example')]),
            }),
            x509.Extension({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': x509.KeyUsage(set(['digital_signature'])),
            }),
        ]])

        seen = {}

        def callback(cri_bytes, signature_algorithm, signature):
            seen['cri_bytes'] = cri_bytes
            seen['algorithm'] = signature_algorithm
            return _verifying_callback(cri_bytes, signature_algorithm, signature)

        result = csr.evaluate_certification_request(request, callback, self._leaf_policy())

        # The callback received the original encoded CertificationRequestInfo
        self.assertEqual(
            request['certification_request_info'].dump(),
            seen['cri_bytes']
        )
        self.assertEqual('sha256_rsa', seen['algorithm']['algorithm'].native)

        self.assertEqual('eval-test.example', result.subject.native['common_name'])
        self.assertEqual('rsa', result.public_key['algorithm'].native['algorithm'])
        self.assertEqual(2, len(result.extensions))

        san, key_usage = result.extensions
        self.assertEqual('2.5.29.17', san.oid)
        self.assertEqual('subject_alt_name', san.name)
        self.assertEqual(False, san.critical)
        self.assertEqual(['eval-test.example'], san.value.parsed.native)
        self.assertEqual(csr.ExtensionSource('extension_request', 0, 0), san.source)
        self.assertEqual('2.5.29.15', key_usage.oid)
        self.assertEqual(True, key_usage.critical)
        self.assertEqual(csr.ExtensionSource('extension_request', 0, 1), key_usage.source)

    def test_evaluate_rejects_bad_signature(self):
        request = _build_csr([[
            x509.Extension({
                'extn_id': 'key_usage',
                'extn_value': x509.KeyUsage(set(['digital_signature'])),
            }),
        ]], tamper_signature=True)

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

        self.assertEqual('signature', cm.exception.stage)

    def test_evaluate_rejects_callback_exception(self):
        request = _build_csr([[]])

        def callback(cri_bytes, signature_algorithm, signature):
            raise RuntimeError('boom')

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(request, callback, self._leaf_policy())

        self.assertEqual('signature', cm.exception.stage)

    def test_evaluate_rejects_ca_request(self):
        # A validly-signed request asking for CA privileges and a key usage
        # that conflicts with them
        request = _build_csr([[
            x509.Extension({
                'extn_id': 'basic_constraints',
                'critical': True,
                'extn_value': x509.BasicConstraints({'ca': True, 'path_len_constraint': 0}),
            }),
            x509.Extension({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': x509.KeyUsage(set(['digital_signature'])),
            }),
        ]])

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

        self.assertEqual('extensions', cm.exception.stage)
        self.assertIn('CA', str(cm.exception))

    def test_evaluate_rejects_ca_key_usage_combination(self):
        # CA key usages requested without CA basic constraints
        request = _build_csr([[
            x509.Extension({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': x509.KeyUsage(set(['key_cert_sign', 'crl_sign'])),
            }),
        ]])

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

        self.assertEqual('extensions', cm.exception.stage)

    def test_evaluate_allows_ca_with_explicit_policy(self):
        request = _build_csr([[
            x509.Extension({
                'extn_id': 'basic_constraints',
                'critical': True,
                'extn_value': x509.BasicConstraints({'ca': True}),
            }),
            x509.Extension({
                'extn_id': 'key_usage',
                'critical': True,
                'extn_value': x509.KeyUsage(set(['key_cert_sign', 'crl_sign'])),
            }),
        ]])

        policy = self._leaf_policy(allow_ca=True)
        result = csr.evaluate_certification_request(request, _verifying_callback, policy)

        self.assertEqual(2, len(result.extensions))

    def test_evaluate_rejects_duplicate_extension_request(self):
        # Two extensionRequest attributes, the second smuggling in a
        # conflicting CA constraint
        request = _build_csr([
            [
                x509.Extension({
                    'extn_id': 'subject_alt_name',
                    'extn_value': x509.GeneralNames([x509.GeneralName('dns_name', 'eval-test.example')]),
                }),
            ],
            [
                x509.Extension({
                    'extn_id': 'basic_constraints',
                    'critical': True,
                    'extn_value': x509.BasicConstraints({'ca': True}),
                }),
            ],
        ])

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

        self.assertEqual('attributes', cm.exception.stage)

    def test_evaluate_rejects_unknown_critical_extension(self):
        request = _build_csr([[
            x509.Extension({
                'extn_id': '1.2.3.4',
                'critical': True,
                'extn_value': b'\x05\x00',
            }),
        ]])

        with self.assertRaises(csr.CSREvaluationError) as cm:
            csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

        self.assertEqual('extensions', cm.exception.stage)

    def test_evaluate_drops_unknown_noncritical_extension(self):
        request = _build_csr([[
            x509.Extension({
                'extn_id': 'subject_alt_name',
                'extn_value': x509.GeneralNames([x509.GeneralName('dns_name', 'eval-test.example')]),
            }),
            x509.Extension({
                'extn_id': '1.2.3.4',
                'extn_value': b'\x05\x00',
            }),
        ]])

        result = csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

        self.assertEqual(1, len(result.extensions))
        self.assertEqual('2.5.29.17', result.extensions[0].oid)

    def test_evaluation_errors_do_not_leak_key_or_request(self):
        requests = [
            _build_csr([[
                x509.Extension({
                    'extn_id': 'basic_constraints',
                    'critical': True,
                    'extn_value': x509.BasicConstraints({'ca': True}),
                }),
            ]]),
            _build_csr([
                [x509.Extension({
                    'extn_id': 'key_usage',
                    'extn_value': x509.KeyUsage(set(['digital_signature'])),
                })],
                [x509.Extension({
                    'extn_id': 'subject_alt_name',
                    'extn_value': x509.GeneralNames([x509.GeneralName('dns_name', 'eval-test.example')]),
                })],
            ]),
        ]

        for request in requests:
            with self.assertRaises(csr.CSREvaluationError) as cm:
                csr.evaluate_certification_request(request, _verifying_callback, self._leaf_policy())

            message = str(cm.exception)
            # No private key material
            self.assertNotIn(str(_TEST_RSA_D), message)
            # No part of the encoded request body
            self.assertNotIn(request.dump().hex(), message)
            self.assertNotIn(
                request['certification_request_info'].dump().hex(),
                message
            )
