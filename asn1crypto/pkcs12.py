# coding: utf-8

"""
ASN.1 type classes for PKCS#12 files. Exports the following items:

 - CertBag()
 - CrlBag()
 - inspect_pfx()
 - Pfx()
 - SafeBag()
 - SecretBag()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib

from ._ordereddict import OrderedDict
from ._types import byte_cls, str_cls
from .algos import DigestInfo
from .cms import ContentInfo, SignedData
from .core import (
    Any,
    BMPString,
    Integer,
    ObjectIdentifier,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
)
from .keys import (
    EncryptedPrivateKeyInfo,
    Null,
    OctetBitString,
    PrivateKeyInfo,
    PublicKeyAlgorithm,
    PublicKeyAlgorithmId,
    PublicKeyInfo,
    RSAPublicKey,
)
from .pem import detect as pem_detect, unarmor
from .x509 import Certificate, KeyPurposeId


# The structures in this file are taken from https://tools.ietf.org/html/rfc7292

class MacData(Sequence):
    _fields = [
        ('mac', DigestInfo),
        ('mac_salt', OctetString),
        ('iterations', Integer, {'default': 1}),
    ]


class Version(Integer):
    _map = {
        3: 'v3'
    }


class AttributeType(ObjectIdentifier):
    _map = {
        # https://tools.ietf.org/html/rfc2985#page-18
        '1.2.840.113549.1.9.20': 'friendly_name',
        '1.2.840.113549.1.9.21': 'local_key_id',
        # https://support.microsoft.com/en-us/kb/287547
        '1.3.6.1.4.1.311.17.1': 'microsoft_local_machine_keyset',
        # https://github.com/frohoff/jdk8u-dev-jdk/blob/master/src/share/classes/sun/security/pkcs12/PKCS12KeyStore.java
        # this is a set of OIDs, representing key usage, the usual value is a SET of one element OID 2.5.29.37.0
        '2.16.840.1.113894.746875.1.1': 'trusted_key_usage',
    }


class SetOfAny(SetOf):
    _child_spec = Any


class SetOfBMPString(SetOf):
    _child_spec = BMPString


class SetOfOctetString(SetOf):
    _child_spec = OctetString


class SetOfKeyPurposeId(SetOf):
    _child_spec = KeyPurposeId


class Attribute(Sequence):
    _fields = [
        ('type', AttributeType),
        ('values', None),
    ]

    _oid_specs = {
        'friendly_name': SetOfBMPString,
        'local_key_id': SetOfOctetString,
        'microsoft_csp_name': SetOfBMPString,
        'trusted_key_usage': SetOfKeyPurposeId,
    }

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class Attributes(SetOf):
    _child_spec = Attribute


class Pfx(Sequence):
    _fields = [
        ('version', Version),
        ('auth_safe', ContentInfo),
        ('mac_data', MacData, {'optional': True})
    ]

    _authenticated_safe = None

    @property
    def authenticated_safe(self):
        if self._authenticated_safe is None:
            content = self['auth_safe']['content']
            if isinstance(content, SignedData):
                content = content['content_info']['content']
            self._authenticated_safe = AuthenticatedSafe.load(content.native)
        return self._authenticated_safe


class AuthenticatedSafe(SequenceOf):
    _child_spec = ContentInfo


class BagId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.12.10.1.1': 'key_bag',
        '1.2.840.113549.1.12.10.1.2': 'pkcs8_shrouded_key_bag',
        '1.2.840.113549.1.12.10.1.3': 'cert_bag',
        '1.2.840.113549.1.12.10.1.4': 'crl_bag',
        '1.2.840.113549.1.12.10.1.5': 'secret_bag',
        '1.2.840.113549.1.12.10.1.6': 'safe_contents',
    }


class CertId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.22.1': 'x509',
        '1.2.840.113549.1.9.22.2': 'sdsi',
    }


class CertBag(Sequence):
    _fields = [
        ('cert_id', CertId),
        ('cert_value', ParsableOctetString, {'explicit': 0}),
    ]

    _oid_pair = ('cert_id', 'cert_value')
    _oid_specs = {
        'x509': Certificate,
    }


class CrlBag(Sequence):
    _fields = [
        ('crl_id', ObjectIdentifier),
        ('crl_value', OctetString, {'explicit': 0}),
    ]


class SecretBag(Sequence):
    _fields = [
        ('secret_type_id', ObjectIdentifier),
        ('secret_value', OctetString, {'explicit': 0}),
    ]


class SafeContents(SequenceOf):
    pass


class SafeBag(Sequence):
    _fields = [
        ('bag_id', BagId),
        ('bag_value', Any, {'explicit': 0}),
        ('bag_attributes', Attributes, {'optional': True}),
    ]

    _oid_pair = ('bag_id', 'bag_value')
    _oid_specs = {
        'key_bag': PrivateKeyInfo,
        'pkcs8_shrouded_key_bag': EncryptedPrivateKeyInfo,
        'cert_bag': CertBag,
        'crl_bag': CrlBag,
        'secret_bag': SecretBag,
        'safe_contents': SafeContents
    }


SafeContents._child_spec = SafeBag


class PfxInspectionError(ValueError):
    """
    An error that prevents a PKCS#12 inspection from being started
    """

    def __init__(self, message, code=None, location=None):
        super(PfxInspectionError, self).__init__(message)
        self.code = code
        self.location = location


def _ordered_result(keys_and_values):
    output = OrderedDict()
    for key, value in keys_and_values:
        output[key] = value
    return output


def _join_location(location, child):
    if location is None:
        return child
    return '%s/%s' % (location, child)


def _algorithm_description(algorithm):
    oid = algorithm['algorithm']
    name = oid.native
    if name == oid.dotted:
        return oid.dotted
    return '%s (%s)' % (name, oid.dotted)


def _bag_attributes(safe_bag):
    attributes = safe_bag['bag_attributes']
    output = []
    for index in range(len(attributes)):
        try:
            attribute = attributes[index]
            output.append(_ordered_result((
                ('type', attribute['type'].native),
                ('values', list(attribute['values'].native)),
            )))
        except Exception:
            output.append(_ordered_result((
                ('type', 'unknown'),
                ('values', []),
                ('parse_error', True),
            )))
    return output


def _attribute_values(attributes, attribute_type):
    values = []
    for attribute in attributes:
        if attribute['type'] == attribute_type:
            values.extend(attribute['values'])
    return values


def _public_key_description(public_key_info):
    return _ordered_result((
        ('algorithm', public_key_info.algorithm),
        ('bit_size', public_key_info.bit_size),
        ('sha256_fingerprint', hashlib.sha256(public_key_info.dump()).hexdigest()),
    ))


def _rsa_public_key_info(private_key_info):
    rsa_private_key = private_key_info['private_key'].parsed
    rsa_public_key = RSAPublicKey()
    rsa_public_key['modulus'] = rsa_private_key['modulus']
    rsa_public_key['public_exponent'] = rsa_private_key['public_exponent']

    algorithm = PublicKeyAlgorithm()
    algorithm_name = 'rsassa_pss' if private_key_info.algorithm == 'rsassa_pss' else 'rsa'
    algorithm['algorithm'] = PublicKeyAlgorithmId(algorithm_name)
    algorithm['parameters'] = Null()

    public_key_info = PublicKeyInfo()
    public_key_info['algorithm'] = algorithm
    public_key_info['public_key'] = rsa_public_key
    return public_key_info


def _ec_public_key_info(private_key_info):
    ec_private_key = private_key_info['private_key'].parsed
    public_key = ec_private_key['public_key']
    if public_key.native is None:
        return None

    algorithm = PublicKeyAlgorithm()
    algorithm['algorithm'] = PublicKeyAlgorithmId('ec')
    private_algorithm = private_key_info['private_key_algorithm']
    if 'parameters' in private_algorithm:
        algorithm['parameters'] = private_algorithm['parameters']
    else:
        algorithm['parameters'] = Null()

    public_key_info = PublicKeyInfo()
    public_key_info['algorithm'] = algorithm
    public_key_info['public_key'] = OctetBitString(public_key.native)
    return public_key_info


def _dsa_public_key_info(private_key_info):
    parameters = private_key_info['private_key_algorithm']['parameters']
    private_value = private_key_info['private_key'].parsed.native
    public_value = pow(parameters['g'].native, private_value, parameters['p'].native)

    algorithm = PublicKeyAlgorithm()
    algorithm['algorithm'] = PublicKeyAlgorithmId('dsa')
    algorithm['parameters'] = parameters

    public_key_info = PublicKeyInfo()
    public_key_info['algorithm'] = algorithm
    public_key_info['public_key'] = Integer(public_value)
    return public_key_info


def _public_key_info_from_private(private_key_info):
    algorithm = private_key_info.algorithm
    if algorithm in ('rsa', 'rsassa_pss'):
        return _rsa_public_key_info(private_key_info)
    if algorithm == 'ec':
        return _ec_public_key_info(private_key_info)
    if algorithm == 'dsa':
        return _dsa_public_key_info(private_key_info)
    return None


def _identity_from_public_key_info(public_key_info):
    return hashlib.sha256(
        public_key_info['algorithm'].dump() + byte_cls(public_key_info['public_key'])
    ).digest()


class _PfxInspector(object):

    def __init__(self, pfx_bytes, password, password_verifier, decryption_callback):
        self.original = pfx_bytes
        self.password = password
        self.password_verifier = password_verifier
        self.decryption_callback = decryption_callback

        self.issues = []
        self.certificates = []
        self.private_keys = []
        self.unknown_bags = []
        self.containers = []
        self.verified = False
        self.authentication = None

        self.pfx = None
        self._certificate_index = 0
        self._private_key_index = 0

    def inspect(self):
        self.pfx = Pfx.load(self.original)
        self._authenticate()
        self._inspect_authenticated_safe()
        try:
            self._associate_entries()
        except Exception as e:
            self._add_issue(
                'error',
                'association_error',
                '%s: %s' % (type(e).__name__, str(e)),
                'safe_bags'
            )

        return _ordered_result((
            ('verified', self.verified),
            ('authentication', self.authentication),
            ('certificates', self.certificates),
            ('private_keys', self.private_keys),
            ('unknown_bags', self.unknown_bags),
            ('containers', self.containers),
            ('issues', self.issues),
            ('errors', [issue for issue in self.issues if issue['severity'] == 'error']),
            ('warnings', [issue for issue in self.issues if issue['severity'] != 'error']),
        ))

    def _add_issue(self, severity, code, message, location):
        issue = _ordered_result((
            ('severity', severity),
            ('code', code),
            ('message', message),
            ('location', location),
        ))
        self.issues.append(issue)
        return issue

    def _authenticate(self):
        auth_safe = self.pfx['auth_safe']
        content_type = auth_safe['content_type'].native
        mac_data = self.pfx['mac_data']

        if content_type == 'signed_data':
            self.verified = False
            self.authentication = _ordered_result((
                ('status', 'unverified'),
                ('mechanism', 'signed_data'),
                ('reason', 'signed_authenticated_safe_is_not_verified_by_callback'),
            ))
            self._add_issue(
                'warning',
                'signed_authenticated_safe_unverified',
                'The AuthenticatedSafe is signed, but no signature verification was performed',
                'auth_safe'
            )
            return

        if content_type != 'data':
            self.verified = False
            self.authentication = _ordered_result((
                ('status', 'unverified'),
                ('mechanism', content_type),
                ('reason', 'unsupported_authenticated_safe_content_type'),
            ))
            self._add_issue(
                'error',
                'unsupported_authenticated_safe_content_type',
                'The PFX auth_safe content type is %s' % content_type,
                'auth_safe'
            )
            return

        if mac_data.native is None:
            self.verified = False
            self.authentication = _ordered_result((
                ('status', 'unverified'),
                ('mechanism', 'none'),
                ('reason', 'no_mac_data'),
            ))
            self._add_issue(
                'warning',
                'missing_mac',
                'The PFX has no MAC data, so its contents are not authenticated',
                'mac_data'
            )
            return

        if self.password_verifier is None:
            self.verified = False
            self.authentication = _ordered_result((
                ('status', 'unverified'),
                ('mechanism', 'mac'),
                ('reason', 'missing_password_verifier'),
            ))
            self._add_issue(
                'error',
                'missing_password_verifier',
                'A password verifier callback is required when MAC data is present',
                'mac_data'
            )
            return

        context = _ordered_result((
            ('location', 'mac_data'),
            ('password', self.password),
            ('auth_safe', auth_safe['content'].native),
            ('mac_data', mac_data),
            ('pfx', self.pfx),
        ))
        try:
            accepted = self.password_verifier(self.password, self.pfx, context)
        except Exception as e:
            accepted = False
            self._add_issue(
                'error',
                'password_verifier_error',
                '%s: %s' % (type(e).__name__, str(e)),
                'mac_data'
            )

        self.verified = bool(accepted)
        self.authentication = _ordered_result((
            ('status', 'verified' if self.verified else 'failed'),
            ('mechanism', 'mac'),
            ('reason', None if self.verified else 'password_verifier_returned_false'),
        ))
        if not self.verified and not self._issue_exists('password_verifier_error', 'mac_data'):
            self._add_issue(
                'error',
                'password_verification_failed',
                'The password verifier callback did not accept the password',
                'mac_data'
            )

    def _issue_exists(self, code, location):
        for issue in self.issues:
            if issue['code'] == code and issue['location'] == location:
                return True
        return False

    def _inspect_authenticated_safe(self):
        auth_safe = self.pfx['auth_safe']
        content_type = auth_safe['content_type'].native
        if content_type not in ('data', 'signed_data'):
            return

        content = auth_safe['content']
        if content_type == 'signed_data':
            content = content['content_info']['content']

        try:
            authenticated_safe = AuthenticatedSafe.load(content.native)
        except Exception as e:
            self._add_issue(
                'error',
                'malformed_authenticated_safe',
                '%s: %s' % (type(e).__name__, str(e)),
                'auth_safe/content'
            )
            return

        for index, content_info in enumerate(authenticated_safe):
            location = 'authenticated_safe[%d]' % index
            try:
                self._inspect_content_info(content_info, location)
            except Exception as e:
                self._add_issue(
                    'error',
                    'malformed_content_info',
                    '%s: %s' % (type(e).__name__, str(e)),
                    location
                )

    def _inspect_content_info(self, content_info, location):
        content_type = content_info['content_type'].native

        if content_type == 'data':
            self._load_safe_contents(content_info['content'].native, location + '/content')
            return

        if content_type == 'encrypted_data':
            encrypted_data = content_info['content']
            content_info_data = encrypted_data['encrypted_content_info']
            plain_bytes = self._decrypt_content_info(content_info_data, location)
            if plain_bytes is None:
                return
            self._load_safe_contents(plain_bytes, location + '/encrypted_content')
            return

        if content_type == 'signed_data':
            signed_data = content_info['content']
            nested_info = signed_data['content_info']
            if nested_info['content_type'].native == 'data':
                self._load_safe_contents(
                    nested_info['content'].native,
                    location + '/signed_content'
                )
            else:
                self._add_issue(
                    'warning',
                    'unverified_nested_signed_data',
                    'Nested SignedData content was not inspected',
                    location
                )
            return

        self._add_issue(
            'warning',
            'unknown_content_info',
            'Unsupported AuthenticatedSafe content type %s' % content_type,
            location
        )

    def _load_safe_contents(self, content_bytes, location):
        try:
            safe_contents = SafeContents.load(content_bytes)
        except Exception as e:
            self._add_issue(
                'error',
                'malformed_safe_contents',
                '%s: %s' % (type(e).__name__, str(e)),
                location
            )
            return
        self._inspect_safe_contents(safe_contents, location)

    def _inspect_safe_contents(self, safe_contents, location):
        for index in range(len(safe_contents)):
            bag_location = _join_location(location, 'safe_bags[%d]' % index)
            try:
                safe_bag = safe_contents[index]
                self._inspect_safe_bag(safe_bag, bag_location)
            except Exception as e:
                self._add_issue(
                    'error',
                    'malformed_safe_bag',
                    '%s: %s' % (type(e).__name__, str(e)),
                    bag_location
                )

    def _decrypt_content_info(self, content_info_data, location):
        algorithm = content_info_data['content_encryption_algorithm']
        encrypted = content_info_data['encrypted_content'].native
        return self._decrypt(algorithm, encrypted, location, 'content_info')

    def _decrypt(self, algorithm, encrypted, location, target_type):
        oid = algorithm['algorithm']
        algorithm_name = oid.native
        if algorithm_name == oid.dotted:
            self._add_issue(
                'error',
                'unknown_encryption_algorithm',
                'Unknown encryption algorithm OID %s' % oid.dotted,
                _join_location(location, 'encryption_algorithm')
            )
            return None

        if self.decryption_callback is None:
            self._add_issue(
                'error',
                'missing_decryption_callback',
                'No caller callback is available for %s' % _algorithm_description(algorithm),
                _join_location(location, 'encryption_algorithm')
            )
            return None

        context = _ordered_result((
            ('location', location),
            ('target', target_type),
            ('password', self.password),
            ('algorithm', algorithm),
            ('encrypted_data', encrypted),
            ('authenticated', self.verified),
        ))
        try:
            plain_bytes = self.decryption_callback(algorithm, encrypted, context)
        except Exception as e:
            self._add_issue(
                'error',
                'decryption_callback_error',
                '%s: %s' % (type(e).__name__, str(e)),
                location
            )
            return None

        if not isinstance(plain_bytes, byte_cls):
            self._add_issue(
                'error',
                'invalid_decryption_callback_result',
                'Decryption callback returned %s instead of a byte string' % type(plain_bytes).__name__,
                location
            )
            return None
        return plain_bytes

    def _entry_status(self):
        return 'verified' if self.verified else 'unverified'

    def _inspect_safe_bag(self, safe_bag, location):
        bag_id = safe_bag['bag_id'].native
        attributes = _bag_attributes(safe_bag)

        if bag_id == 'safe_contents':
            self.containers.append(_ordered_result((
                ('type', 'safe_contents'),
                ('location', location),
                ('attributes', attributes),
                ('verified', self.verified),
            )))
            self._inspect_safe_contents(safe_bag['bag_value'], location + '/safe_bags')
            return

        if bag_id == 'cert_bag':
            self._inspect_cert_bag(safe_bag, attributes, location)
            return

        if bag_id in ('key_bag', 'pkcs8_shrouded_key_bag'):
            self._inspect_key_bag(safe_bag, bag_id, attributes, location)
            return

        self.unknown_bags.append(_ordered_result((
            ('type', bag_id),
            ('location', location),
            ('attributes', attributes),
            ('verified', self.verified),
        )))
        self._add_issue(
            'warning',
            'unknown_bag',
            'Unsupported PKCS#12 bag type %s' % bag_id,
            location
        )

    def _inspect_cert_bag(self, safe_bag, attributes, location):
        cert_bag = safe_bag['bag_value']
        cert_id = cert_bag['cert_id'].native
        if cert_id != 'x509':
            self.unknown_bags.append(_ordered_result((
                ('type', 'cert_bag'),
                ('certificate_type', cert_id),
                ('location', location),
                ('attributes', attributes),
                ('verified', self.verified),
            )))
            self._add_issue(
                'warning',
                'unknown_certificate_bag',
                'Unsupported certificate bag type %s' % cert_id,
                location + '/cert_id'
            )
            return

        try:
            certificate = cert_bag['cert_value'].parsed
            public_key_info = certificate.public_key
            identity = _identity_from_public_key_info(public_key_info)
        except Exception as e:
            self.unknown_bags.append(_ordered_result((
                ('type', 'cert_bag'),
                ('certificate_type', cert_id),
                ('location', location),
                ('attributes', attributes),
                ('verified', self.verified),
            )))
            self._add_issue(
                'error',
                'malformed_certificate',
                '%s: %s' % (type(e).__name__, str(e)),
                location + '/cert_value'
            )
            return

        index = self._certificate_index
        self._certificate_index += 1
        self.certificates.append(_ordered_result((
            ('id', index),
            ('type', 'x509'),
            ('location', location),
            ('attributes', attributes),
            ('authentication', self._entry_status()),
            ('verified', self.verified),
            ('public_key', _public_key_description(public_key_info)),
            ('public_key_identity', identity),
            ('private_key_present', False),
            ('association_status', 'none'),
            ('private_key_locations', []),
            ('candidate_locations', []),
            ('ambiguities', []),
        )))

    def _inspect_key_bag(self, safe_bag, bag_id, attributes, location):
        index = self._private_key_index
        self._private_key_index += 1
        encrypted = bag_id == 'pkcs8_shrouded_key_bag'
        encryption_algorithm = None
        private_key_info = None

        if encrypted:
            encrypted_key = safe_bag['bag_value']
            algorithm = encrypted_key['encryption_algorithm']
            encryption_algorithm = _algorithm_description(algorithm)
            plain_bytes = self._decrypt(
                algorithm,
                encrypted_key['encrypted_data'].native,
                location,
                'pkcs8_shrouded_key_bag'
            )
            if plain_bytes is not None:
                try:
                    private_key_info = PrivateKeyInfo.load(plain_bytes)
                except Exception as e:
                    self._add_issue(
                        'error',
                        'malformed_private_key_info',
                        '%s: %s' % (type(e).__name__, str(e)),
                        location + '/decrypted_private_key'
                    )
        else:
            try:
                private_key_info = safe_bag['bag_value']
            except Exception as e:
                self._add_issue(
                    'error',
                    'malformed_private_key',
                    '%s: %s' % (type(e).__name__, str(e)),
                    location + '/bag_value'
                )

        public_key = None
        identity = None
        if private_key_info is not None:
            try:
                public_key_info = _public_key_info_from_private(private_key_info)
                if public_key_info is not None:
                    public_key = _public_key_description(public_key_info)
                    identity = _identity_from_public_key_info(public_key_info)
            except Exception as e:
                self._add_issue(
                    'error',
                    'private_key_identity_error',
                    '%s: %s' % (type(e).__name__, str(e)),
                    location
                )

        self.private_keys.append(_ordered_result((
            ('id', index),
            ('type', bag_id),
            ('location', location),
            ('attributes', attributes),
            ('authentication', self._entry_status()),
            ('verified', self.verified),
            ('private_key_present', True),
            ('encrypted', encrypted),
            ('encryption_algorithm', encryption_algorithm),
            ('public_key', public_key),
            ('public_key_identity', identity),
            ('certificate_present', False),
            ('association_status', 'unverified' if identity is None else 'none'),
            ('certificate_locations', []),
            ('candidate_locations', []),
            ('ambiguities', []),
        )))

    def _local_key_ids(self, entry):
        return [
            value for value in _attribute_values(entry['attributes'], 'local_key_id')
            if isinstance(value, byte_cls)
        ]

    def _friendly_names(self, entry):
        return [
            value for value in _attribute_values(entry['attributes'], 'friendly_name')
            if isinstance(value, str_cls)
        ]

    def _associate_entries(self):
        certificates_by_identity = {}
        private_keys_by_identity = {}
        certificates_by_local_key = {}
        private_keys_by_local_key = {}
        certificates_by_friendly_name = {}
        private_keys_by_friendly_name = {}

        for certificate in self.certificates:
            certificates_by_identity.setdefault(certificate['public_key_identity'], []).append(certificate)
            for local_key_id in set(self._local_key_ids(certificate)):
                certificates_by_local_key.setdefault(local_key_id, []).append(certificate)
            for friendly_name in set(self._friendly_names(certificate)):
                certificates_by_friendly_name.setdefault(friendly_name, []).append(certificate)

        for private_key in self.private_keys:
            if private_key['public_key_identity'] is not None:
                private_keys_by_identity.setdefault(
                    private_key['public_key_identity'], []
                ).append(private_key)
            for local_key_id in set(self._local_key_ids(private_key)):
                private_keys_by_local_key.setdefault(local_key_id, []).append(private_key)
            for friendly_name in set(self._friendly_names(private_key)):
                private_keys_by_friendly_name.setdefault(friendly_name, []).append(private_key)

        all_identities = sorted(
            set(certificates_by_identity) | set(private_keys_by_identity),
            key=lambda value: value
        )
        for identity in all_identities:
            certificates = certificates_by_identity.get(identity, [])
            private_keys = private_keys_by_identity.get(identity, [])
            if not certificates or not private_keys:
                continue

            locations = [entry['location'] for entry in certificates + private_keys]
            if len(certificates) == 1 and len(private_keys) == 1:
                if self.verified:
                    self._record_verified_association(certificates[0], private_keys[0])
                else:
                    self._record_unverified_association(certificates[0], private_keys[0])
            else:
                self._record_ambiguity(
                    certificates + private_keys,
                    'one_to_many_public_key_identity',
                    'Multiple bags share the same authenticated public key identity',
                    locations
                )

        all_local_key_ids = sorted(
            set(certificates_by_local_key) | set(private_keys_by_local_key),
            key=lambda value: value
        )
        for local_key_id in all_local_key_ids:
            certificates = certificates_by_local_key.get(local_key_id, [])
            private_keys = private_keys_by_local_key.get(local_key_id, [])
            self._associate_local_key_group(local_key_id, certificates, private_keys)

        all_friendly_names = sorted(
            set(certificates_by_friendly_name) | set(private_keys_by_friendly_name)
        )
        for friendly_name in all_friendly_names:
            certificates = certificates_by_friendly_name.get(friendly_name, [])
            private_keys = private_keys_by_friendly_name.get(friendly_name, [])
            self._associate_friendly_name_group(friendly_name, certificates, private_keys)

    def _record_verified_association(self, certificate, private_key):
        if self._has_attribute_conflict(certificate, private_key):
            locations = [certificate['location'], private_key['location']]
            self._record_ambiguity(
                [certificate, private_key],
                'attribute_conflict',
                'The certificate and private key attributes conflict',
                locations
            )
            return

        certificate['private_key_present'] = True
        certificate['association_status'] = 'verified'
        certificate['private_key_locations'] = [private_key['location']]

        private_key['certificate_present'] = True
        private_key['association_status'] = 'verified'
        private_key['certificate_locations'] = [certificate['location']]

    def _record_unverified_association(self, certificate, private_key):
        if self._has_attribute_conflict(certificate, private_key):
            self._record_ambiguity(
                [certificate, private_key],
                'attribute_conflict',
                'The certificate and private key attributes conflict',
                [certificate['location'], private_key['location']]
            )
            return
        certificate['private_key_present'] = True
        certificate['association_status'] = 'unverified'
        certificate['candidate_locations'] = [private_key['location']]
        private_key['certificate_present'] = True
        private_key['association_status'] = 'unverified'
        private_key['candidate_locations'] = [certificate['location']]

    def _record_ambiguity(self, entries, code, message, locations):
        certificate_locations = [
            entry['location'] for entry in entries if 'encrypted' not in entry
        ]
        private_key_locations = [
            entry['location'] for entry in entries if 'encrypted' in entry
        ]
        for entry in entries:
            if 'encrypted' not in entry:
                entry['private_key_present'] = True
                entry['candidate_locations'] = private_key_locations
            else:
                entry['certificate_present'] = True
                entry['candidate_locations'] = certificate_locations
            entry['association_status'] = 'ambiguous'
            entry['ambiguities'].append(_ordered_result((
                ('code', code),
                ('message', message),
                ('locations', list(locations)),
            )))
        self._add_issue('warning', code, message, ', '.join(locations))

    def _has_attribute_conflict(self, certificate, private_key):
        certificate_names = set(self._friendly_names(certificate))
        private_key_names = set(self._friendly_names(private_key))
        certificate_ids = set(self._local_key_ids(certificate))
        private_key_ids = set(self._local_key_ids(private_key))
        if certificate_names and private_key_names and certificate_names != private_key_names:
            return True
        if certificate_ids and private_key_ids and certificate_ids != private_key_ids:
            return True
        return False

    def _associate_local_key_group(self, local_key_id, certificates, private_keys):
        local_key_id_hex = local_key_id.hex() if hasattr(local_key_id, 'hex') else local_key_id.encode('hex')
        locations = [entry['location'] for entry in certificates + private_keys]
        if not certificates or not private_keys:
            return

        known_identities = set()
        for entry in certificates + private_keys:
            identity = entry.get('public_key_identity')
            if identity is not None:
                known_identities.add(identity)

        if len(known_identities) > 1:
            self._record_ambiguity(
                certificates + private_keys,
                'local_key_id_conflict',
                'Bags share localKeyId %s but contain different public key identities' % local_key_id_hex,
                locations
            )
            return

        if len(certificates) > 1 or len(private_keys) > 1:
            self._record_ambiguity(
                certificates + private_keys,
                'one_to_many_local_key_id',
                'localKeyId %s refers to multiple bags' % local_key_id_hex,
                locations
            )
            return

        if certificates and private_keys:
            certificate = certificates[0]
            private_key = private_keys[0]
            if certificate['public_key_identity'] == private_key['public_key_identity']:
                return
            if private_key['public_key_identity'] is None:
                if self._has_attribute_conflict(certificate, private_key):
                    self._record_ambiguity(
                        [certificate, private_key],
                        'attribute_conflict',
                        'The certificate and private key attributes conflict',
                        locations
                    )
                    return
                certificate['private_key_present'] = True
                if certificate['association_status'] == 'none':
                    certificate['association_status'] = 'unverified'
                certificate['candidate_locations'] = [private_key['location']]
                private_key['certificate_present'] = True
                if private_key['association_status'] == 'none':
                    private_key['association_status'] = 'unverified'
                private_key['candidate_locations'] = [certificate['location']]
            elif certificate['public_key_identity'] != private_key['public_key_identity']:
                self._record_ambiguity(
                    [certificate, private_key],
                    'local_key_id_conflict',
                    'localKeyId %s does not match the public key identity' % local_key_id_hex,
                    locations
                )

    def _associate_friendly_name_group(self, friendly_name, certificates, private_keys):
        if not certificates or not private_keys:
            return

        locations = [entry['location'] for entry in certificates + private_keys]

        if len(certificates) > 1 or len(private_keys) > 1:
            self._record_ambiguity(
                certificates + private_keys,
                'one_to_many_friendly_name',
                'friendlyName %r refers to multiple bags' % friendly_name,
                locations
            )
            return

        certificate = certificates[0]
        private_key = private_keys[0]
        if private_key['public_key_identity'] is None:
            certificate['private_key_present'] = True
            if certificate['association_status'] == 'none':
                certificate['association_status'] = 'unverified'
            certificate['candidate_locations'] = [private_key['location']]
            private_key['certificate_present'] = True
            if private_key['association_status'] == 'none':
                private_key['association_status'] = 'unverified'
            private_key['candidate_locations'] = [certificate['location']]
        elif certificate['public_key_identity'] != private_key['public_key_identity']:
            self._record_ambiguity(
                [certificate, private_key],
                'friendly_name_conflict',
                'friendlyName %r does not match the public key identity' % friendly_name,
                locations
            )


def inspect_pfx(pfx_bytes, password=None, password_verifier=None, decryption_callback=None,
                password_callback=None, decrypt_callback=None):
    """
    Inspects a PKCS#12 PFX without installing any certificates or private keys.

    Password verification and encryption are intentionally performed by caller
    supplied callbacks. The returned structure contains public-key metadata and
    private-key presence flags only; private-key bytes are never placed in the
    result.

    :param pfx_bytes:
        A byte string containing DER- or PEM-encoded PFX data

    :param password:
        An arbitrary value passed to the caller callbacks. It is usually a
        byte string, but a unicode string or None may be useful depending on
        the callback implementation.

    :param password_verifier:
        A callable invoked as ``password_verifier(password, pfx, context)`` for
        PFX files containing MAC data. It must return a true value only when the
        password and MAC are accepted.

    :param decryption_callback:
        A callable invoked as
        ``decryption_callback(algorithm, encrypted_data, context)`` for both
        encrypted AuthenticatedSafe data and shrouded PKCS#8 keys. It must
        return the decrypted byte string.

    :return:
        An OrderedDict-like dict with stable keys: ``verified``,
        ``authentication``, ``certificates``, ``private_keys``,
        ``unknown_bags``, ``containers``, ``issues``, ``errors`` and
        ``warnings``.
    """

    if not isinstance(pfx_bytes, byte_cls):
        raise PfxInspectionError(
            'pfx_bytes must be a byte string, not %s' % type(pfx_bytes).__name__,
            code='invalid_pfx_input'
        )

    if password_callback is not None and password_verifier is None:
        password_verifier = password_callback
    if decrypt_callback is not None and decryption_callback is None:
        decryption_callback = decrypt_callback

    if password_verifier is not None and not callable(password_verifier):
        raise PfxInspectionError(
            'password_verifier must be callable',
            code='invalid_password_verifier'
        )
    if decryption_callback is not None and not callable(decryption_callback):
        raise PfxInspectionError(
            'decryption_callback must be callable',
            code='invalid_decryption_callback'
        )

    der_bytes = pfx_bytes
    if pem_detect(pfx_bytes):
        try:
            _, _, der_bytes = unarmor(pfx_bytes)
        except Exception as e:
            raise PfxInspectionError(
                '%s: %s' % (type(e).__name__, str(e)),
                code='invalid_pem',
                location='pfx_bytes'
            )

    try:
        inspector = _PfxInspector(
            der_bytes,
            password,
            password_verifier,
            decryption_callback
        )
        return inspector.inspect()
    except PfxInspectionError:
        raise
    except Exception as e:
        raise PfxInspectionError(
            '%s: %s' % (type(e).__name__, str(e)),
            code='malformed_pfx',
            location='pfx_bytes'
        )


inspect_pkcs12 = inspect_pfx
