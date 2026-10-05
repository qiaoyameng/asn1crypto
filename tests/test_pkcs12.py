# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
import sys

from asn1crypto import algos, cms, core, keys, pkcs12, x509
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class PKCS12Tests(unittest.TestCase):

    def test_parse_pfx(self):
        with open(os.path.join(fixtures_dir, 'test-tripledes.p12'), 'rb') as f:
            info = pkcs12.Pfx.load(f.read())

        self.assertEqual(
            'v3',
            info['version'].native
        )

        auth_safe = info['auth_safe']

        self.assertEqual(
            'data',
            auth_safe['content_type'].native
        )

        self.assertEqual(
            2,
            len(info.authenticated_safe)
        )

        for i, content_info in enumerate(info.authenticated_safe):
            if i == 0:
                self.assertEqual(
                    'encrypted_data',
                    content_info['content_type'].native
                )
            else:
                self.assertEqual(
                    'data',
                    content_info['content_type'].native
                )
                safe_contents = pkcs12.SafeContents.load(content_info['content'].native)
                self.assertEqual(
                    1,
                    len(safe_contents)
                )
                bag_attributes = safe_contents[0]['bag_attributes']
                self.assertEqual(
                    2,
                    len(bag_attributes)
                )
                self.assertEqual(
                    'local_key_id',
                    bag_attributes[0]['type'].native
                )
                self.assertEqual(
                    [b'\x95\xd7\xcf\xd7&\x80\x02\x94Q\xc2}X\xee\xd7\x9eiQ\xc0\x10P'],
                    bag_attributes[0]['values'].native
                )
                self.assertEqual(
                    'friendly_name',
                    bag_attributes[1]['type'].native
                )
                self.assertEqual(
                    ['PKCS#12 Test'],
                    bag_attributes[1]['values'].native
                )

    def test_parse_certbag(self):
        '''test to parse the java oid "2.16.840.1.113894.746875.1.1"'''
        with open(os.path.join(fixtures_dir, 'certbag.der'), 'rb') as f:
            certbag = pkcs12.SafeBag.load(f.read())

        self.assertEqual(
            2,
            len(certbag['bag_attributes'])
        )

        attr_0 = certbag['bag_attributes'][0]

        self.assertEqual(
            'friendly_name',
            attr_0['type'].native
        )

        self.assertEqual(
            ['testcertificate'],
            attr_0['values'].native
        )

        attr_1 = certbag['bag_attributes'][1]

        self.assertEqual(
            'trusted_key_usage',
            attr_1['type'].native
        )

        self.assertEqual(
            ['any_extended_key_usage'],
            attr_1['values'].native
        )

    def test_inspect_pfx_stable_nested_duplicates_and_associations(self):
        key_a = _rsa_private_key_info(35, 7, 11, 5, 7)
        key_b = _rsa_private_key_info(77, 7, 43, 7, 11)

        matching_key = _safe_bag('key_bag', key_a, ['Duplicate Display Name'], [b'key-a'])
        matching_cert = _safe_bag(
            'cert_bag',
            _x509_cert_bag(35, 7, 'First Duplicate'),
            ['Duplicate Display Name', 'Duplicate Display Name'],
            [b'key-a']
        )
        nested = _safe_bag(
            'safe_contents',
            pkcs12.SafeContents([matching_cert]),
            ['Container Friendly Name'],
            [b'container']
        )
        duplicate_cert = _safe_bag(
            'cert_bag',
            _x509_cert_bag(35, 7, 'Duplicate Identity'),
            ['Duplicate Display Name'],
            [b'key-a']
        )
        conflict_cert = _safe_bag(
            'cert_bag',
            _x509_cert_bag(77, 7, 'Second Cert'),
            ['Second'],
            [b'conflict']
        )
        conflict_key_b = _safe_bag('key_bag', key_b, ['Second'], [b'conflict'])
        conflict_key_a = _safe_bag('key_bag', key_a, ['Wrong Key'], [b'conflict'])

        pfx_bytes = _pfx([
            _data_content_info(pkcs12.SafeContents([matching_key])),
            _data_content_info(pkcs12.SafeContents([
                nested,
                duplicate_cert,
                conflict_cert,
                conflict_key_b,
                conflict_key_a
            ])),
        ], mac_data=True)
        verifier = lambda password, pfx, context: True

        result = pkcs12.inspect_pfx(pfx_bytes, password_verifier=verifier)
        repeated = pkcs12.inspect_pfx(pfx_bytes, password_verifier=verifier)

        self.assertEqual(result, repeated)
        self.assertTrue(result['verified'])
        self.assertEqual(3, len(result['certificates']))
        self.assertEqual(3, len(result['private_keys']))
        self.assertEqual(1, len(result['containers']))

        nested_cert = result['certificates'][0]
        self.assertIn('/safe_bags[0]/safe_bags/safe_bags[0]', nested_cert['location'])
        nested_names = [
            attribute['values']
            for attribute in nested_cert['attributes']
            if attribute['type'] == 'friendly_name'
        ][0]
        self.assertEqual(
            ['Duplicate Display Name', 'Duplicate Display Name'],
            nested_names
        )
        self.assertEqual('ambiguous', nested_cert['association_status'])
        self.assertTrue(nested_cert['private_key_present'])
        self.assertTrue(any(
            issue['code'] == 'one_to_many_public_key_identity'
            and nested_cert['location'] in issue['location']
            for issue in result['issues']
        ))

        codes = [issue['code'] for issue in result['issues']]
        self.assertIn('local_key_id_conflict', codes)
        self.assertIn('one_to_many_friendly_name', codes)
        self.assertIn('one_to_many_public_key_identity', codes)
        self.assertTrue(all(issue['location'] for issue in result['issues']))

    def test_inspect_pfx_decryption_callback(self):
        private_key = _rsa_private_key_info(35, 7, 11, 5, 7)
        cert_bag = _safe_bag(
            'cert_bag',
            _x509_cert_bag(35, 7, 'Decrypted'),
            ['Decrypted'],
            [b'encrypted']
        )
        encrypted_key = _safe_bag(
            'pkcs8_shrouded_key_bag',
            _encrypted_key_bag(private_key),
            ['Decrypted'],
            [b'encrypted']
        )
        safe_contents = pkcs12.SafeContents([cert_bag, encrypted_key])
        pfx_bytes = _pfx([_encrypted_content_info(safe_contents.dump())], mac_data=True)

        result = pkcs12.inspect_pfx(
            pfx_bytes,
            password_verifier=lambda password, pfx, context: True,
            decryption_callback=_xor_decrypt
        )

        self.assertEqual([], result['errors'])
        self.assertEqual('verified', result['certificates'][0]['association_status'])
        self.assertEqual('verified', result['private_keys'][0]['association_status'])
        self.assertTrue(result['private_keys'][0]['encrypted'])
        self.assertIn('pbes2', result['private_keys'][0]['encryption_algorithm'])
        self.assertNotIn('private_key', result['private_keys'][0])

    def test_inspect_pfx_errors_are_located(self):
        private_key = _rsa_private_key_info(35, 7, 11, 5, 7)
        other_private_key = _rsa_private_key_info(77, 7, 43, 7, 11)
        encrypted_key = _encrypted_key_bag(private_key)
        failing_encrypted_key = _encrypted_key_bag(other_private_key)
        unknown_algorithm = algos.EncryptionAlgorithm()
        unknown_algorithm['algorithm'] = algos.EncryptionAlgorithmId('1.2.3.4')
        unknown_algorithm['parameters'] = core.OctetString(b'params')
        encrypted_key['encryption_algorithm'] = unknown_algorithm

        unknown_bag = pkcs12.SafeBag()
        unknown_bag['bag_id'] = pkcs12.BagId('1.2.3.5')
        unknown_bag['bag_value'] = core.OctetString(b'unknown', explicit=0)

        safe_contents = pkcs12.SafeContents([
            _safe_bag('pkcs8_shrouded_key_bag', encrypted_key, ['Broken'], [b'broken']),
            _safe_bag('pkcs8_shrouded_key_bag', failing_encrypted_key, ['Fails'], [b'fails']),
            unknown_bag,
        ])
        pfx_bytes = _pfx([_data_content_info(safe_contents)], mac_data=True)

        def failing_verifier(password, pfx, context):
            raise RuntimeError('verifier failed')

        def failing_decrypt(algorithm, encrypted_data, context):
            raise RuntimeError('decrypt failed')

        result = pkcs12.inspect_pfx(
            pfx_bytes,
            password_verifier=failing_verifier,
            decryption_callback=failing_decrypt
        )

        self.assertFalse(result['verified'])
        self.assertEqual(2, len(result['private_keys']))
        self.assertEqual(1, len(result['unknown_bags']))
        codes = [issue['code'] for issue in result['issues']]
        self.assertIn('password_verifier_error', codes)
        self.assertIn('decryption_callback_error', codes)
        self.assertIn('unknown_encryption_algorithm', codes)
        self.assertIn('unknown_bag', codes)
        self.assertTrue(all(issue['location'] for issue in result['issues']))
        self.assertNotEqual([], result['errors'])

    def test_inspect_pfx_without_mac_marks_public_matches_unverified(self):
        private_key = _rsa_private_key_info(35, 7, 11, 5, 7)
        safe_contents = pkcs12.SafeContents([
            _safe_bag('key_bag', private_key, ['No MAC'], [b'no-mac']),
            _safe_bag(
                'cert_bag',
                _x509_cert_bag(35, 7, 'No MAC'),
                ['No MAC'],
                [b'no-mac']
            ),
        ])
        pfx_bytes = _pfx([_data_content_info(safe_contents)])

        result = pkcs12.inspect_pfx(pfx_bytes)

        self.assertFalse(result['verified'])
        self.assertEqual('unverified', result['authentication']['status'])
        self.assertEqual('unverified', result['certificates'][0]['association_status'])
        self.assertEqual('unverified', result['private_keys'][0]['association_status'])
        self.assertTrue(result['certificates'][0]['private_key_present'])


def _rsa_private_key_info(modulus, public_exponent, private_exponent, prime1, prime2):
    rsa_key = keys.RSAPrivateKey()
    values = [
        0,
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        private_exponent % (prime1 - 1),
        private_exponent % (prime2 - 1),
        pow(prime2, -1, prime1),
    ]
    names = [
        'version',
        'modulus',
        'public_exponent',
        'private_exponent',
        'prime1',
        'prime2',
        'exponent1',
        'exponent2',
        'coefficient',
    ]
    for name, value in zip(names, values):
        rsa_key[name] = value

    info = keys.PrivateKeyInfo()
    info['version'] = 0
    algorithm = keys.PrivateKeyAlgorithm()
    algorithm['algorithm'] = 'rsa'
    algorithm['parameters'] = core.Null()
    info['private_key_algorithm'] = algorithm
    info['private_key'] = rsa_key
    return info


def _x509_cert_bag(modulus, public_exponent, common_name):
    rsa_public_key = keys.RSAPublicKey()
    rsa_public_key['modulus'] = modulus
    rsa_public_key['public_exponent'] = public_exponent

    public_key_info = keys.PublicKeyInfo()
    algorithm = keys.PublicKeyAlgorithm()
    algorithm['algorithm'] = 'rsa'
    algorithm['parameters'] = core.Null()
    public_key_info['algorithm'] = algorithm
    public_key_info['public_key'] = rsa_public_key

    signature_algorithm = x509.SignedDigestAlgorithm()
    signature_algorithm['algorithm'] = 'sha256_rsa'
    signature_algorithm['parameters'] = core.Null()
    name = x509.Name.build({'common_name': common_name})

    tbs = x509.TbsCertificate()
    tbs['version'] = 'v3'
    tbs['serial_number'] = 1
    tbs['signature'] = signature_algorithm
    tbs['issuer'] = name
    tbs['subject'] = name
    validity = x509.Validity()
    validity['not_before'] = x509.Time(name='utc_time', value=x509.UTCTime('20000101000000Z'))
    validity['not_after'] = x509.Time(name='utc_time', value=x509.UTCTime('20300101000000Z'))
    tbs['validity'] = validity
    tbs['subject_public_key_info'] = public_key_info

    certificate = x509.Certificate()
    certificate['tbs_certificate'] = tbs
    certificate['signature_algorithm'] = signature_algorithm
    certificate['signature_value'] = b'\x00'

    bag = pkcs12.CertBag()
    bag['cert_id'] = 'x509'
    bag['cert_value'] = certificate
    return bag


def _attributes(friendly_names=None, local_key_ids=None):
    attributes = []
    if friendly_names is not None:
        values = pkcs12.SetOfBMPString()
        for value in friendly_names:
            values.append(value)
        attribute = pkcs12.Attribute()
        attribute['type'] = 'friendly_name'
        attribute['values'] = values
        attributes.append(attribute)
    if local_key_ids is not None:
        values = pkcs12.SetOfOctetString()
        for value in local_key_ids:
            values.append(value)
        attribute = pkcs12.Attribute()
        attribute['type'] = 'local_key_id'
        attribute['values'] = values
        attributes.append(attribute)
    return pkcs12.Attributes(attributes)


def _safe_bag(bag_id, value, friendly_names=None, local_key_ids=None):
    bag = pkcs12.SafeBag()
    bag['bag_id'] = bag_id
    bag['bag_value'] = value
    bag['bag_attributes'] = _attributes(friendly_names, local_key_ids)
    return bag


def _data_content_info(safe_contents):
    content_info = cms.ContentInfo()
    content_info['content_type'] = 'data'
    content_info['content'] = safe_contents.dump()
    return content_info


def _encrypted_content_info(plain_bytes, marker=b'x'):
    encrypted_bytes = bytes(bytearray(value ^ ord(marker.decode('ascii')) for value in bytearray(plain_bytes)))
    algorithm = _pbes2_algorithm()

    info = cms.EncryptedContentInfo()
    info['content_type'] = 'data'
    info['content_encryption_algorithm'] = algorithm
    info['encrypted_content'] = encrypted_bytes

    encrypted_data = cms.EncryptedData()
    encrypted_data['version'] = 0
    encrypted_data['encrypted_content_info'] = info

    content_info = cms.ContentInfo()
    content_info['content_type'] = 'encrypted_data'
    content_info['content'] = encrypted_data
    return content_info


def _encrypted_key_bag(private_key_info, marker=b'k'):
    encrypted_bytes = bytes(bytearray(
        value ^ ord(marker.decode('ascii')) for value in bytearray(private_key_info.dump())
    ))
    algorithm = _pbes2_algorithm()

    encrypted_key = keys.EncryptedPrivateKeyInfo()
    encrypted_key['encryption_algorithm'] = algorithm
    encrypted_key['encrypted_data'] = encrypted_bytes
    return encrypted_key


def _pbes2_algorithm():
    params = algos.Pbes2Params()
    kdf = algos.KdfAlgorithm()
    kdf['algorithm'] = 'pbkdf2'
    kdf['parameters'] = {
        'salt': ('specified', core.OctetString(b'saltsalt')),
        'iteration_count': 1
    }
    encryption_scheme = algos.EncryptionAlgorithm()
    encryption_scheme['algorithm'] = 'tripledes_3key'
    encryption_scheme['parameters'] = core.OctetString(b'iviviviv')
    params['key_derivation_func'] = kdf
    params['encryption_scheme'] = encryption_scheme

    algorithm = algos.EncryptionAlgorithm()
    algorithm['algorithm'] = 'pbes2'
    algorithm['parameters'] = params
    return algorithm


def _pfx(content_infos, mac_data=False):
    authenticated_safe = pkcs12.AuthenticatedSafe(content_infos)
    pfx = pkcs12.Pfx()
    pfx['version'] = 3
    content_info = cms.ContentInfo()
    content_info['content_type'] = 'data'
    content_info['content'] = authenticated_safe.dump()
    pfx['auth_safe'] = content_info
    if mac_data:
        digest_info = algos.DigestInfo()
        digest_info['digest_algorithm'] = {'algorithm': 'sha256'}
        digest_info['digest'] = b'digest'
        pfx_mac_data = pkcs12.MacData()
        pfx_mac_data['mac'] = digest_info
        pfx_mac_data['mac_salt'] = b'salt'
        pfx_mac_data['iterations'] = 1
        pfx['mac_data'] = pfx_mac_data
    return pfx.dump()


def _xor_decrypt(algorithm, encrypted_data, context):
    marker = b'x' if context['target'] == 'content_info' else b'k'
    return bytes(bytearray(value ^ ord(marker.decode('ascii')) for value in bytearray(encrypted_data)))
