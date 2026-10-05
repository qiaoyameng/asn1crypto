# coding: utf-8

"""
ASN.1 type classes for PKCS#12 files. Exports the following items:

 - CertBag()
 - CrlBag()
 - Pfx()
 - SafeBag()
 - SecretBag()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib

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
from ._types import byte_cls
from .keys import PrivateKeyInfo, EncryptedPrivateKeyInfo
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


# ---------------------------------------------------------------------------
# PKCS#12 inspection API
#
# The inspection API never installs any of the certificates or private keys
# contained in a PFX into the operating system. It also never performs
# password verification or decryption on its own - every cryptographic
# operation is performed by an explicit caller-supplied callback so that the
# calling application stays in control of its cryptographic backends.
# ---------------------------------------------------------------------------


class P12InspectError(Exception):
    """
    Base class for errors reported through the PKCS#12 inspection callbacks
    """

    def __init__(self, message):
        super(P12InspectError, self).__init__(message)
        self.message = message


class P12PasswordError(P12InspectError):
    """
    Raised by a password callback to indicate that the supplied password is
    incorrect
    """


class P12DecryptionError(P12InspectError):
    """
    Raised by a decryption callback to indicate that decryption failed for a
    reason other than an unsupported algorithm
    """


class P12UnsupportedAlgorithmError(P12InspectError):
    """
    Raised by a decryption callback to indicate that the requested encryption
    algorithm is not supported by the caller
    """


class BagAttribute(object):
    """
    A single attribute attached to a SafeBag, preserving the order in which it
    appeared and allowing duplicate attribute types to be retained.
    """

    def __init__(self, attr_type, value):
        """
        :param attr_type:
            A unicode string of the attribute type - either a mapped name such
            as "friendly_name", or a dotted OID string for unknown attributes

        :param value:
            The native value of a single element of the attribute's value SET
        """
        self.type = attr_type
        self.value = value

    def __eq__(self, other):
        return isinstance(other, BagAttribute) and \
            self.type == other.type and self.value == other.value

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.type, self.value))

    def __repr__(self):
        return 'BagAttribute(%r, %r)' % (self.type, self.value)


class InspectEntry(object):
    """
    Base class for entries discovered while inspecting a PFX
    """

    def __init__(self, path, attributes, authenticated, order):
        # A unicode string locating the entry, e.g. "authenticated_safe[1].bag[0].bag[1]"
        self.path = path
        # A list of BagAttribute objects, including duplicates, in encounter order
        self.attributes = list(attributes)
        # A set of unicode strings: "pfx_mac" and/or "content_signature"
        self.authenticated_by = set(authenticated)
        # An integer used to stabilize the ordering of the inventory
        self.order = order

    @property
    def verified(self):
        """
        :return:
            A boolean - if the entry was only seen through data that passed an
            authentication check (PFX MAC or an outer signature), this is
            True. Entries carried by unauthenticated, tampered or undecrypted
            data are reported as unverified.
        """
        return len(self.authenticated_by) > 0

    def _named_attributes(self, attr_name):
        return [attr.value for attr in self.attributes if attr.type == attr_name]

    @property
    def friendly_names(self):
        """
        :return:
            A list of unicode strings - every friendlyName value attached to
            the bag, duplicates preserved
        """
        return self._named_attributes('friendly_name')

    @property
    def local_key_ids(self):
        """
        :return:
            A list of byte strings - every localKeyId value attached to the
            bag, duplicates preserved
        """
        return self._named_attributes('local_key_id')


class CertificateEntry(InspectEntry):
    """
    A certificate bag found in the PFX. Only public information is exposed -
    the certificate itself contains no private key material.
    """

    def __init__(self, path, attributes, authenticated, order, certificate, cert_type):
        super(CertificateEntry, self).__init__(path, attributes, authenticated, order)
        self.certificate = certificate
        # A unicode string of the cert bag cert_id, e.g. "x509" or a dotted OID
        self.cert_type = cert_type

    @property
    def algorithm(self):
        """
        :return:
            A unicode string of the certificate public key algorithm, e.g.
            "rsa", "dsa", "ec" - or a dotted OID string if unknown
        """
        return self.certificate['tbs_certificate']['subject_public_key_info']['algorithm']['algorithm'].native

    @property
    def bit_size(self):
        """
        :return:
            An integer of the public key bit size
        """
        return self.certificate.public_key.bit_size

    @property
    def public_key_sha256(self):
        """
        :return:
            A byte string of the SHA-256 hash of the DER-encoded
            SubjectPublicKeyInfo, used as the actual public key identity
        """
        return hashlib.sha256(self.certificate['tbs_certificate']['subject_public_key_info'].dump()).digest()

    @property
    def subject(self):
        """
        :return:
            A unicode string of the certificate subject distinguished name
        """
        return self.certificate.subject.human_friendly

    @property
    def serial_number(self):
        """
        :return:
            An integer of the certificate serial number
        """
        return self.certificate.serial_number

    @property
    def sha256_fingerprint(self):
        """
        :return:
            A byte string of the SHA-256 fingerprint of the DER certificate
        """
        return self.certificate.sha256


class PrivateKeyEntry(InspectEntry):
    """
    A private key bag found in the PFX. The private key body is never exposed -
    only a presence marker and public information derived from the key.
    """

    def __init__(self, path, attributes, authenticated, order, bag_type,
                 algorithm=None, bit_size=None, public_key_sha256=None,
                 encrypted_algorithm=None, decryptable=False):
        super(PrivateKeyEntry, self).__init__(path, attributes, authenticated, order)
        # A unicode string: "key_bag" or "pkcs8_shrouded_key_bag"
        self.bag_type = bag_type
        # A unicode string of the key algorithm, e.g. "rsa", or None when the
        # key could not be decrypted / parsed
        self.algorithm = algorithm
        # An integer bit size, or None when not derivable
        self.bit_size = bit_size
        # A byte string SHA-256 of the DER SubjectPublicKeyInfo, or None when
        # the public key identity cannot be derived
        self.public_key_sha256 = public_key_sha256
        # For shrouded key bags, a unicode string of the encryption algorithm
        # name (or dotted OID string); None for plain key bags
        self.encrypted_algorithm = encrypted_algorithm
        # A boolean - whether the key bag was successfully decrypted by the
        # caller's callback. Always True for plain key bags.
        self.decryptable = decryptable

    @property
    def private_key_present(self):
        """
        :return:
            A boolean - always True, since a private key bag exists. The
            private key contents are intentionally not exposed.
        """
        return True


class UnknownEntry(InspectEntry):
    """
    A bag that is not a certificate or private key bag (e.g. a CRL bag, a
    secret bag, or a bag with an unknown bag ID), including unknown bags found
    inside nested SafeContents.
    """

    def __init__(self, path, attributes, authenticated, order, bag_type, parsed=True):
        super(UnknownEntry, self).__init__(path, attributes, authenticated, order)
        # A unicode string of the bag ID - a mapped name or dotted OID string
        self.bag_type = bag_type
        # A boolean - whether the bag value could be parsed against a known spec
        self.parsed = parsed


class InspectIssue(object):
    """
    A locatable problem encountered during inspection. Issues are always
    surfaced instead of being collapsed into a generic "empty certificate
    bundle" result.
    """

    def __init__(self, code, path, message, detail=None):
        # A unicode string, e.g. "callback_error", "unknown_algorithm",
        # "unknown_bag", "association_ambiguous", "mac_invalid", ...
        self.code = code
        # A unicode string locating the problem within the PFX
        self.path = path
        # A human-readable unicode string
        self.message = message
        # Optional structured detail (e.g. an exception object or candidate list)
        self.detail = detail

    def __eq__(self, other):
        return isinstance(other, InspectIssue) and \
            (self.code, self.path, self.message) == (other.code, other.path, other.message)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return 'InspectIssue(%r, %r, %r)' % (self.code, self.path, self.message)


class KeyAssociation(object):
    """
    The result of attempting to associate a private key entry with certificate
    entries. Association first follows friendlyName/localKeyId hints, then
    verifies the actual public key identity (the SubjectPublicKeyInfo SHA-256).
    """

    def __init__(self, key):
        self.key = key
        # A list of (CertificateEntry, unicode status) tuples, where status is
        # one of "confirmed", "identity_mismatch" or "no_identity"
        self.candidates = []
        # None, or the single confirmed CertificateEntry
        self.certificate = None
        # A unicode string: "confirmed", "ambiguous", "no_match", "no_identity"
        self.status = 'no_match'

    @property
    def ambiguous(self):
        return self.status == 'ambiguous'


class P12Inspection(object):
    """
    The result of inspecting a PFX. Contains inventory lists (stable by
    construction order) plus locatable issues. None of the attributes expose
    private key material.
    """

    def __init__(self):
        self.certificates = []
        self.private_keys = []
        self.unknown_bags = []
        self.issues = []
        self.associations = []
        # A unicode string: "valid", "invalid", "absent", "unchecked" or "error"
        self.mac_status = 'absent'
        self.mac_algorithm = None

    def to_dict(self):
        """
        :return:
            A plain dict representation suitable for serialisation. Only
            public-key information and a private-key presence marker are
            included; private key bodies are never present.
        """

        def _entry(entry):
            data = {
                'path': entry.path,
                'verified': entry.verified,
                'authenticated_by': sorted(entry.authenticated_by),
                'friendly_names': entry.friendly_names,
                'local_key_ids': [byte_cls(v) for v in entry.local_key_ids],
                'attributes': [{'type': attr.type, 'value': attr.value} for attr in entry.attributes],
            }
            return data

        output = {
            'mac_status': self.mac_status,
            'mac_algorithm': self.mac_algorithm,
            'certificates': [],
            'private_keys': [],
            'unknown_bags': [],
            'associations': [],
            'issues': [{'code': issue.code, 'path': issue.path, 'message': issue.message}
                       for issue in self.issues],
        }

        for cert in self.certificates:
            cert_data = _entry(cert)
            cert_data.update({
                'cert_type': cert.cert_type,
                'algorithm': cert.algorithm,
                'bit_size': cert.bit_size,
                'public_key_sha256': cert.public_key_sha256,
                'subject': cert.subject,
                'serial_number': cert.serial_number,
                'sha256_fingerprint': cert.sha256_fingerprint,
            })
            output['certificates'].append(cert_data)

        for key in self.private_keys:
            key_data = _entry(key)
            key_data.update({
                'bag_type': key.bag_type,
                'private_key_present': key.private_key_present,
                'decryptable': key.decryptable,
                'encrypted_algorithm': key.encrypted_algorithm,
                'algorithm': key.algorithm,
                'bit_size': key.bit_size,
                'public_key_sha256': key.public_key_sha256,
            })
            output['private_keys'].append(key_data)

        for unknown in self.unknown_bags:
            unknown_data = _entry(unknown)
            unknown_data.update({'bag_type': unknown.bag_type, 'parsed': unknown.parsed})
            output['unknown_bags'].append(unknown_data)

        for association in self.associations:
            output['associations'].append({
                'key_path': association.key.path,
                'status': association.status,
                'certificate_path': association.certificate.path if association.certificate else None,
                'candidates': [
                    {
                        'certificate_path': candidate.path,
                        'status': status,
                        'shared_friendly_names': sorted(
                            set(association.key.friendly_names) & set(candidate.friendly_names)
                        ),
                        'shared_local_key_ids': sorted(
                            set(association.key.local_key_ids) & set(candidate.local_key_ids)
                        ),
                    }
                    for candidate, status in association.candidates
                ],
            })

        return output


def _extract_attributes(safe_bag, path, issues):
    """
    Converts the bag_attributes of a SafeBag into a list of BagAttribute
    objects, preserving duplicates and order.

    :param safe_bag:
        A SafeBag object

    :param path:
        A unicode string of the path to the bag

    :param issues:
        A list of InspectIssue objects to append problems to

    :return:
        A list of BagAttribute objects
    """

    attributes = []
    attrs = safe_bag['bag_attributes']
    if attrs.native is None:
        return attributes

    for attr in attrs:
        try:
            attr_type = attr['type'].native
            values = attr['values']
            if values.native is None:
                continue
            for value in values:
                attributes.append(BagAttribute(attr_type, value.native))
        except Exception as e:
            issues.append(InspectIssue(
                'malformed_attribute',
                path,
                'A bag attribute could not be parsed and was skipped: %s' % e,
                e
            ))
    return attributes


def _public_key_identity(private_key_info):
    """
    Derives the public-key identity of a decrypted PrivateKeyInfo without ever
    exposing the private key body. The identity is the DER encoding of the
    SubjectPublicKeyInfo and its SHA-256 hash, plus the algorithm and bit size.

    :param private_key_info:
        A PrivateKeyInfo object

    :return:
        A 4-element tuple of (algorithm, bit_size, spki_der, spki_sha256),
        where elements may be None if they cannot be derived
    """

    from .keys import PublicKeyAlgorithm, PublicKeyInfo, RSAPublicKey

    algorithm = private_key_info.algorithm

    spki = PublicKeyInfo()
    spki_algorithm = PublicKeyAlgorithm()
    spki_algorithm['algorithm'] = private_key_info['private_key_algorithm']['algorithm']

    if algorithm in ('rsa', 'rsassa_pss'):
        parsed = private_key_info['private_key'].parsed
        rsa_public = RSAPublicKey()
        rsa_public['modulus'] = parsed['modulus']
        rsa_public['public_exponent'] = parsed['public_exponent']
        spki_algorithm['parameters'] = private_key_info['private_key_algorithm']['parameters']
        spki['algorithm'] = spki_algorithm
        spki['public_key'] = rsa_public.dump()
        bit_size = private_key_info.bit_size

    elif algorithm == 'ec':
        parsed = private_key_info['private_key'].parsed
        public_point = parsed['public_key']
        if public_point.native is None:
            return (algorithm, private_key_info.bit_size, None, None)
        spki_algorithm['parameters'] = private_key_info['private_key_algorithm']['parameters']
        spki['algorithm'] = spki_algorithm
        spki['public_key'] = byte_cls(public_point)
        bit_size = private_key_info.bit_size

    elif algorithm == 'dsa':
        params = private_key_info['private_key_algorithm']['parameters']
        x = private_key_info['private_key'].parsed.native
        y = pow(params['g'].native, x, params['p'].native)
        spki_algorithm['parameters'] = params
        spki['algorithm'] = spki_algorithm
        spki['public_key'] = y
        bit_size = private_key_info.bit_size

    else:
        # EdDSA and other opaque key formats cannot have their public key
        # derived from PKCS#8 private key info without key-specific math.
        return (algorithm, None, None, None)

    spki_der = spki.dump()
    return (algorithm, bit_size, spki_der, hashlib.sha256(spki_der).digest())


def _process_safe_bag(safe_bag, path, result, authenticated, counters,
                      decrypt_callback, context):
    """
    Records a single SafeBag into the inspection result and recurses into
    nested SafeContents.

    :param safe_bag:
        A SafeBag object

    :param path:
        A unicode string path locating the bag

    :param result:
        A P12Inspection object

    :param authenticated:
        A set of unicode strings naming the authentication that protected the
        data, e.g. {"pfx_mac"}

    :param counters:
        A dict used to allocate stable order numbers

    :param decrypt_callback:
        The caller-supplied decryption callback (may be None)

    :param context:
        A dict of opaque context data forwarded to callbacks
    """

    bag_id = safe_bag['bag_id'].native
    attributes = _extract_attributes(safe_bag, path, result.issues)

    def _order():
        counters['order'] += 1
        return counters['order']

    if bag_id == 'cert_bag':
        cert_bag = safe_bag['bag_value'].parsed
        cert_id = cert_bag['cert_id'].native
        if cert_id != 'x509':
            entry = UnknownEntry(
                path, attributes, authenticated, _order(),
                'cert_bag:%s' % cert_id
            )
            result.unknown_bags.append(entry)
            result.issues.append(InspectIssue(
                'unknown_cert_type',
                path,
                'Certificate bag contains an unsupported certificate type %r' % cert_id
            ))
            return
        certificate = cert_bag['cert_value'].parsed
        entry = CertificateEntry(
            path, attributes, authenticated, _order(), certificate, cert_id
        )
        result.certificates.append(entry)
        return

    if bag_id == 'key_bag':
        private_key_info = safe_bag['bag_value'].parsed
        try:
            algorithm, bit_size, _spki_der, spki_sha256 = _public_key_identity(private_key_info)
        except Exception as e:
            result.issues.append(InspectIssue(
                'key_parse_error',
                path,
                'Private key could not be parsed to derive its public key identity: %s' % e,
                e
            ))
            algorithm, bit_size, spki_sha256 = None, None, None
        entry = PrivateKeyEntry(
            path, attributes, authenticated, _order(),
            'key_bag', algorithm=algorithm, bit_size=bit_size,
            public_key_sha256=spki_sha256, decryptable=True
        )
        result.private_keys.append(entry)
        return

    if bag_id == 'pkcs8_shrouded_key_bag':
        epki = safe_bag['bag_value'].parsed
        encryption_algorithm = epki['encryption_algorithm']['algorithm'].native
        if decrypt_callback is None:
            entry = PrivateKeyEntry(
                path, attributes, authenticated, _order(),
                'pkcs8_shrouded_key_bag',
                encrypted_algorithm=encryption_algorithm, decryptable=False
            )
            result.private_keys.append(entry)
            result.issues.append(InspectIssue(
                'no_decrypt_callback',
                path,
                'Shrouded private key bag is encrypted with %r but no '
                'decryption callback was provided' % encryption_algorithm
            ))
            return

        try:
            decrypted = decrypt_callback(
                'shrouded_key_bag',
                path,
                epki['encryption_algorithm'],
                epki['encrypted_data'].native,
                context
            )
        except P12UnsupportedAlgorithmError as e:
            entry = PrivateKeyEntry(
                path, attributes, authenticated, _order(),
                'pkcs8_shrouded_key_bag',
                encrypted_algorithm=encryption_algorithm, decryptable=False
            )
            result.private_keys.append(entry)
            result.issues.append(InspectIssue(
                'unknown_algorithm',
                path,
                'Encryption algorithm %r used by the shrouded private key '
                'bag is not supported: %s' % (encryption_algorithm, e.message),
                e
            ))
            return
        except P12PasswordError as e:
            entry = PrivateKeyEntry(
                path, attributes, authenticated, _order(),
                'pkcs8_shrouded_key_bag',
                encrypted_algorithm=encryption_algorithm, decryptable=False
            )
            result.private_keys.append(entry)
            result.issues.append(InspectIssue(
                'password_error',
                path,
                'Password was rejected while decrypting the shrouded '
                'private key bag: %s' % e.message,
                e
            ))
            return
        except P12DecryptionError as e:
            entry = PrivateKeyEntry(
                path, attributes, authenticated, _order(),
                'pkcs8_shrouded_key_bag',
                encrypted_algorithm=encryption_algorithm, decryptable=False
            )
            result.private_keys.append(entry)
            result.issues.append(InspectIssue(
                'decryption_error',
                path,
                'Shrouded private key bag could not be decrypted: %s' % e.message,
                e
            ))
            return
        except Exception as e:
            entry = PrivateKeyEntry(
                path, attributes, authenticated, _order(),
                'pkcs8_shrouded_key_bag',
                encrypted_algorithm=encryption_algorithm, decryptable=False
            )
            result.private_keys.append(entry)
            result.issues.append(InspectIssue(
                'callback_error',
                path,
                'Decryption callback failed for the shrouded private key '
                'bag: %s: %s' % (type(e).__name__, e),
                e
            ))
            return

        from .keys import PrivateKeyInfo
        try:
            private_key_info = PrivateKeyInfo.load(decrypted)
            algorithm, bit_size, _spki_der, spki_sha256 = _public_key_identity(private_key_info)
        except Exception as e:
            result.issues.append(InspectIssue(
                'key_parse_error',
                path,
                'Decrypted private key could not be parsed: %s' % e,
                e
            ))
            algorithm, bit_size, spki_sha256 = None, None, None
        entry = PrivateKeyEntry(
            path, attributes, authenticated, _order(),
            'pkcs8_shrouded_key_bag', algorithm=algorithm, bit_size=bit_size,
            public_key_sha256=spki_sha256,
            encrypted_algorithm=encryption_algorithm, decryptable=True
        )
        result.private_keys.append(entry)
        return

    if bag_id == 'safe_contents':
        nested = safe_bag['bag_value'].parsed
        _walk_safe_contents(nested, path + '.bag', result, authenticated,
                            counters, decrypt_callback, context)
        return

    # crl_bag, secret_bag, or a bag with a completely unknown bag ID
    parsed = True
    try:
        safe_bag['bag_value'].parsed
    except Exception:
        parsed = False
    entry = UnknownEntry(
        path, attributes, authenticated, _order(), bag_id, parsed=parsed
    )
    result.unknown_bags.append(entry)
    result.issues.append(InspectIssue(
        'unknown_bag',
        path,
        'Unrecognised or unsupported bag of type %r was skipped; contents '
        'were not collapsed into an empty certificate inventory' % bag_id
    ))


def _walk_safe_contents(safe_contents, path_prefix, result, authenticated,
                        counters, decrypt_callback, context):
    """
    Walks a SafeContents sequence and every nested SafeContents bag.

    :param safe_contents:
        A SafeContents object (or raw bytes)

    :param path_prefix:
        A unicode string prefix used to locate each bag

    :param result:
        A P12Inspection object

    :param authenticated:
        A set of unicode strings naming the authentication that protected the
        data

    :param counters:
        A dict used to allocate stable order numbers

    :param decrypt_callback:
        The caller-supplied decryption callback (may be None)

    :param context:
        A dict of opaque context data forwarded to callbacks
    """

    if isinstance(safe_contents, byte_cls):
        safe_contents = SafeContents.load(safe_contents)

    for index, safe_bag in enumerate(safe_contents):
        _process_safe_bag(
            safe_bag,
            '%s[%d]' % (path_prefix, index),
            result,
            authenticated,
            counters,
            decrypt_callback,
            context
        )


def _build_associations(result):
    """
    Builds certificate/key candidate associations. Candidates are first
    selected via friendlyName/localKeyId hints (which are just hints and can
    legitimately repeat or collide), then checked against the actual public
    key identity (SubjectPublicKeyInfo SHA-256). Attribute conflicts or one
    (key) to many (certificates) matches are reported as ambiguous instead of
    silently choosing the first candidate.
    """

    for key in result.private_keys:
        association = KeyAssociation(key)

        key_names = set(key.friendly_names)
        key_ids = set(key.local_key_ids)

        candidates = []
        for cert in result.certificates:
            shares_name = bool(key_names & set(cert.friendly_names))
            shares_id = bool(key_ids & set(cert.local_key_ids))
            if not shares_name and not shares_id:
                continue
            if key.public_key_sha256 is None or cert.public_key_sha256 is None:
                status = 'no_identity'
            elif key.public_key_sha256 == cert.public_key_sha256:
                status = 'confirmed'
            else:
                status = 'identity_mismatch'
            candidates.append((cert, status, shares_name, shares_id))

        # If no attribute-based candidate exists but identities are available,
        # the actual public key identity is still checked across all certs.
        if not candidates and key.public_key_sha256 is not None:
            for cert in result.certificates:
                if cert.public_key_sha256 == key.public_key_sha256:
                    candidates.append((cert, 'confirmed', False, False))

        association.candidates = [(cert, status) for cert, status, _, _ in candidates]

        confirmed = [cert for cert, status, _, _ in candidates if status == 'confirmed']

        if key.public_key_sha256 is None:
            association.status = 'no_identity'
            if candidates:
                result.issues.append(InspectIssue(
                    'association_ambiguous',
                    key.path,
                    'Private key public identity cannot be derived; %d '
                    'certificate(s) share attributes with the key but the '
                    'association cannot be verified' % len(candidates),
                    [(cert.path, status) for cert, status, _, _ in candidates]
                ))
        elif len(confirmed) == 1:
            mismatched = [cert for cert, status, _, _ in candidates
                          if status == 'identity_mismatch']
            if mismatched:
                association.status = 'ambiguous'
                result.issues.append(InspectIssue(
                    'association_ambiguous',
                    key.path,
                    'Attributes of %s also point at %d certificate(s) whose '
                    'actual public key does not match the private key' % (
                        confirmed[0].path, len(mismatched)
                    ),
                    [(cert.path, status) for cert, status, _, _ in candidates]
                ))
            else:
                association.status = 'confirmed'
                association.certificate = confirmed[0]
        elif len(confirmed) > 1:
            association.status = 'ambiguous'
            result.issues.append(InspectIssue(
                'association_ambiguous',
                key.path,
                'Private key matches the actual public key of %d distinct '
                'certificates; refusing to pick the first one' % len(confirmed),
                [(cert.path, status) for cert, status, _, _ in candidates]
            ))
        else:
            if candidates:
                association.status = 'ambiguous'
                result.issues.append(InspectIssue(
                    'association_ambiguous',
                    key.path,
                    '%d certificate(s) share friendlyName/localKeyId '
                    'attributes with the key, but none matches the actual '
                    'public key identity (attribute conflict)' % len(candidates),
                    [(cert.path, status) for cert, status, _, _ in candidates]
                ))
            else:
                association.status = 'no_match'

        result.associations.append(association)


def inspect_pfx(pfx_data, password_callback=None, decrypt_callback=None,
                mac_callback=None, context=None):
    """
    Inspects the contents of a PKCS#12 PFX without installing any of the
    certificates or private keys into the operating system. Password
    verification and all decryption are performed by explicit caller-supplied
    callbacks - this function itself never derives keys or decrypts data.

    :param pfx_data:
        A byte string of the DER-encoded PFX

    :param password_callback:
        An optional callable invoked when a password is required. Called as
        ``password_callback(path, context)`` and must return a byte string
        password. Raising P12PasswordError signals an incorrect password.

    :param decrypt_callback:
        An optional callable performing decryption. Called as
        ``decrypt_callback(kind, path, algorithm, encrypted_data, context)``
        where *kind* is "authenticated_safe" for a PBE-encrypted AuthenticatedSafe
        ContentInfo or "shrouded_key_bag" for a PKCS#8 EncryptedPrivateKeyInfo,
        *algorithm* is the asn1crypto AlgorithmIdentifier object, and
        *encrypted_data* is a byte string. Must return the plaintext bytes.
        May raise P12UnsupportedAlgorithmError (unknown algorithm),
        P12PasswordError (bad password) or P12DecryptionError (other failure).
        If password_callback is provided, the byte string password is also
        passed as the last argument instead of *context*.

    :param mac_callback:
        An optional callable verifying the PFX integrity password/MAC. Called as
        ``mac_callback(mac_data, auth_safe_encoded, context)`` where *mac_data*
        is the MacData object and *auth_safe_encoded* is the raw encoded
        AuthenticatedSafe the MAC is computed over. Must return True/False, or
        raise P12PasswordError to report a wrong password.

    :param context:
        An arbitrary value forwarded unchanged to every callback

    :return:
        A P12Inspection object. Encrypted containers that could not be
        decrypted, unknown bags and unknown algorithms are all reported as
        locatable entries/issues rather than as an empty certificate bundle.
    """

    if not isinstance(pfx_data, byte_cls):
        raise TypeError('pfx_data must be a byte string, not %s' % type(pfx_data).__name__)

    result = P12Inspection()
    counters = {'order': 0}

    try:
        pfx = Pfx.load(pfx_data)
    except Exception as e:
        result.issues.append(InspectIssue(
            'parse_error',
            'pfx',
            'Data could not be parsed as a PKCS#12 PFX: %s' % e,
            e
        ))
        return result

    mac_present = pfx['mac_data'].native is not None
    mac_valid = False
    if mac_present:
        mac_data = pfx['mac_data']
        result.mac_algorithm = mac_data['mac']['digest_algorithm']['algorithm'].native
        if mac_callback is None:
            result.mac_status = 'unchecked'
            result.issues.append(InspectIssue(
                'mac_unchecked',
                'pfx.mac_data',
                'PFX MAC data is present but no MAC verification callback '
                'was supplied; entries are marked unverified'
            ))
        else:
            try:
                auth_safe_raw = pfx['auth_safe']['content'].native
                mac_ok = bool(mac_callback(mac_data, auth_safe_raw, context))
                if mac_ok:
                    result.mac_status = 'valid'
                    mac_valid = True
                else:
                    result.mac_status = 'invalid'
                    result.issues.append(InspectIssue(
                        'mac_invalid',
                        'pfx.mac_data',
                        'PFX MAC verification returned False; entries are '
                        'marked unverified'
                    ))
            except P12PasswordError as e:
                result.mac_status = 'invalid'
                result.issues.append(InspectIssue(
                    'mac_password_error',
                    'pfx.mac_data',
                    'Password rejected while verifying the PFX MAC: %s' % e.message,
                    e
                ))
            except Exception as e:
                result.mac_status = 'error'
                result.issues.append(InspectIssue(
                    'callback_error',
                    'pfx.mac_data',
                    'MAC verification callback failed: %s: %s' % (
                        type(e).__name__, e
                    ),
                    e
                ))
    else:
        result.mac_status = 'absent'
        result.issues.append(InspectIssue(
            'mac_absent',
            'pfx.mac_data',
            'PFX has no MAC data; entries cannot be authenticated and are '
            'marked unverified'
        ))

    def _decrypt(kind, path, algorithm, encrypted_bytes):
        if decrypt_callback is None:
            return None
        return decrypt_callback(kind, path, algorithm, encrypted_bytes, context)

    try:
        authenticated_safe = pfx.authenticated_safe
    except Exception as e:
        result.issues.append(InspectIssue(
            'parse_error',
            'pfx.authenticated_safe',
            'AuthenticatedSafe could not be parsed: %s' % e,
            e
        ))
        _build_associations(result)
        return result

    for safe_index, content_info in enumerate(authenticated_safe):
        safe_path = 'authenticated_safe[%d]' % safe_index
        content_type = content_info['content_type'].native

        if content_type == 'data':
            authenticated = {'pfx_mac'} if mac_valid else set()
            try:
                safe_contents = SafeContents.load(content_info['content'].native)
            except Exception as e:
                result.issues.append(InspectIssue(
                    'parse_error',
                    safe_path,
                    'Data ContentInfo did not contain a valid SafeContents: %s' % e,
                    e
                ))
                continue
            _walk_safe_contents(
                safe_contents, safe_path + '.bag', result, authenticated,
                counters, decrypt_callback, context
            )

        elif content_type == 'encrypted_data':
            encrypted_data = content_info['content']
            eci = encrypted_data['encrypted_content_info']
            algorithm = eci['content_encryption_algorithm']
            encrypted_bytes = eci['encrypted_content'].native
            if encrypted_bytes is None:
                encrypted_bytes = b''

            if password_callback is not None:
                try:
                    password_callback(safe_path, context)
                except P12PasswordError as e:
                    result.issues.append(InspectIssue(
                        'password_error',
                        safe_path,
                        'Password rejected for the encrypted AuthenticatedSafe: %s' % e.message,
                        e
                    ))
                    continue
                except Exception as e:
                    result.issues.append(InspectIssue(
                        'callback_error',
                        safe_path,
                        'Password callback failed: %s: %s' % (
                            type(e).__name__, e
                        ),
                        e
                    ))
                    continue

            try:
                plaintext = _decrypt(
                    'authenticated_safe', safe_path, algorithm,
                    encrypted_bytes
                )
            except P12UnsupportedAlgorithmError as e:
                result.issues.append(InspectIssue(
                    'unknown_algorithm',
                    safe_path,
                    'AuthenticatedSafe encryption algorithm %r is not '
                    'supported: %s' % (algorithm['algorithm'].native, e.message),
                    e
                ))
                continue
            except P12PasswordError as e:
                result.issues.append(InspectIssue(
                    'password_error',
                    safe_path,
                    'Password rejected while decrypting the AuthenticatedSafe: %s' % e.message,
                    e
                ))
                continue
            except P12DecryptionError as e:
                result.issues.append(InspectIssue(
                    'decryption_error',
                    safe_path,
                    'AuthenticatedSafe could not be decrypted: %s' % e.message,
                    e
                ))
                continue
            except Exception as e:
                result.issues.append(InspectIssue(
                    'callback_error',
                    safe_path,
                    'Decryption callback failed on the AuthenticatedSafe: %s: %s' % (
                        type(e).__name__, e
                    ),
                    e
                ))
                continue

            if plaintext is None:
                result.issues.append(InspectIssue(
                    'no_decrypt_callback',
                    safe_path,
                    'AuthenticatedSafe is encrypted with %r but no decryption '
                    'callback was provided' % algorithm['algorithm'].native
                ))
                continue

            authenticated = {'pfx_mac'} if mac_valid else set()
            try:
                safe_contents = SafeContents.load(plaintext)
            except Exception as e:
                result.issues.append(InspectIssue(
                    'decryption_error',
                    safe_path,
                    'Decrypted AuthenticatedSafe bytes are not a valid '
                    'SafeContents: %s' % e,
                    e
                ))
                continue

            _walk_safe_contents(
                safe_contents, safe_path + '.bag', result, authenticated,
                counters, decrypt_callback, context
            )

        else:
            result.issues.append(InspectIssue(
                'unknown_content_type',
                safe_path,
                'AuthenticatedSafe contains an unsupported ContentInfo of '
                'type %r' % content_type
            ))

    _build_associations(result)
    return result
