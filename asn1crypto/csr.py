# coding: utf-8

"""
ASN.1 type classes for certificate signing requests (CSR). Exports the
following items:

 - CertificationRequest()
 - CSREvaluationError()
 - CSREvaluationPolicy()
 - CSREvaluationResult()
 - CandidateExtension()
 - ExtensionSource()
 - evaluate_certification_request()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .algos import SignedDigestAlgorithm
from .core import (
    Any,
    BitString,
    BMPString,
    Integer,
    ObjectIdentifier,
    OctetBitString,
    Sequence,
    SetOf,
    UTF8String
)
from .keys import PublicKeyInfo
from .pem import detect as _pem_detect, unarmor as _pem_unarmor
from .x509 import DirectoryString, ExtensionId, Extensions, Name


# The structures in this file are taken from https://tools.ietf.org/html/rfc2986
# and https://tools.ietf.org/html/rfc2985


class Version(Integer):
    _map = {
        0: 'v1',
    }


class CSRAttributeType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.7': 'challenge_password',
        '1.2.840.113549.1.9.9': 'extended_certificate_attributes',
        '1.2.840.113549.1.9.14': 'extension_request',
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/a5eaae36-e9f3-4dc5-a687-bfa7115954f1
        '1.3.6.1.4.1.311.13.2.2': 'microsoft_enrollment_csp_provider',
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/7c677cba-030d-48be-ba2b-01e407705f34
        '1.3.6.1.4.1.311.13.2.3': 'microsoft_os_version',
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/64e5ff6d-c6dd-4578-92f7-b3d895f9b9c7
        '1.3.6.1.4.1.311.21.20': 'microsoft_request_client_info',
    }


class SetOfDirectoryString(SetOf):
    _child_spec = DirectoryString


class Attribute(Sequence):
    _fields = [
        ('type', ObjectIdentifier),
        ('values', SetOf, {'spec': Any}),
    ]


class SetOfAttributes(SetOf):
    _child_spec = Attribute


class SetOfExtensions(SetOf):
    _child_spec = Extensions


class MicrosoftEnrollmentCSProvider(Sequence):
    _fields = [
        ('keyspec', Integer),
        ('cspname', BMPString),  # cryptographic service provider name
        ('signature', BitString),
    ]


class SetOfMicrosoftEnrollmentCSProvider(SetOf):
    _child_spec = MicrosoftEnrollmentCSProvider


class MicrosoftRequestClientInfo(Sequence):
    _fields = [
        ('clientid', Integer),
        ('machinename', UTF8String),
        ('username', UTF8String),
        ('processname', UTF8String),
    ]


class SetOfMicrosoftRequestClientInfo(SetOf):
    _child_spec = MicrosoftRequestClientInfo


class CRIAttribute(Sequence):
    _fields = [
        ('type', CSRAttributeType),
        ('values', Any),
    ]

    _oid_pair = ('type', 'values')
    _oid_specs = {
        'challenge_password': SetOfDirectoryString,
        'extended_certificate_attributes': SetOfAttributes,
        'extension_request': SetOfExtensions,
        'microsoft_enrollment_csp_provider': SetOfMicrosoftEnrollmentCSProvider,
        'microsoft_os_version': SetOfDirectoryString,
        'microsoft_request_client_info': SetOfMicrosoftRequestClientInfo,
    }


class CRIAttributes(SetOf):
    _child_spec = CRIAttribute


class CertificationRequestInfo(Sequence):
    _fields = [
        ('version', Version),
        ('subject', Name),
        ('subject_pk_info', PublicKeyInfo),
        ('attributes', CRIAttributes, {'implicit': 0, 'optional': True}),
    ]


class CertificationRequest(Sequence):
    _fields = [
        ('certification_request_info', CertificationRequestInfo),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


# The stages at which evaluate_certification_request() may reject a request.
# Exposed so callers can programmatically distinguish a bad signature from a
# policy violation.
EVALUATION_STAGE_SIGNATURE = 'signature'
EVALUATION_STAGE_ATTRIBUTES = 'attributes'
EVALUATION_STAGE_EXTENSIONS = 'extensions'


class CSREvaluationError(ValueError):
    """
    An error raised when a certification request fails evaluation.

    The message intentionally only ever contains stage names, dotted OIDs,
    attribute type names and indexes - never key material, extension values
    or the encoded request itself.
    """

    # One of the EVALUATION_STAGE_* constants
    stage = None

    def __init__(self, stage, message):
        self.stage = stage
        ValueError.__init__(self, message)


def _extension_oid_names():
    """
    Builds a reverse lookup of extension short names to dotted OIDs

    :return:
        A dict mapping unicode extension names to dotted OID unicode strings
    """

    return dict((name, dotted) for dotted, name in ExtensionId._map.items())


class CSREvaluationPolicy(object):
    """
    An explicit allowlist policy controlling which requested extensions a
    signing service is willing to consider. Nothing is permitted unless it
    is opted into here - in particular CA privileges are never granted by
    default.
    """

    # A frozenset of dotted OID unicode strings the service may honor
    allowed_extensions = None

    # If duplicate attributes of the same type are tolerated
    allow_duplicate_attributes = False

    # If critical extensions outside the allowlist are dropped instead of
    # rejected
    allow_unknown_critical = False

    # If a request for basic constraints CA:TRUE may be honored
    allow_ca = False

    def __init__(self, allowed_extensions, allow_duplicate_attributes=False,
                 allow_unknown_critical=False, allow_ca=False):
        """
        :param allowed_extensions:
            An iterable of extension OIDs (dotted unicode strings) or short
            names (e.g. "subject_alt_name") that the service is willing to
            honor. Must be provided explicitly.

        :param allow_duplicate_attributes:
            A bool - if duplicate attributes of the same type (e.g. two
            extensionRequest attributes) should be merged instead of
            rejected

        :param allow_unknown_critical:
            A bool - if critical extensions outside of allowed_extensions
            should be silently dropped instead of rejected

        :param allow_ca:
            A bool - if a request for basic constraints CA:TRUE may be
            honored. Defaults to False so CA privileges are never granted
            implicitly.
        """

        if allowed_extensions is None:
            raise ValueError('allowed_extensions must be provided explicitly')

        names = _extension_oid_names()
        self.allowed_extensions = frozenset(
            names.get(oid_or_name, oid_or_name)
            for oid_or_name in allowed_extensions
        )
        self.allow_duplicate_attributes = bool(allow_duplicate_attributes)
        self.allow_unknown_critical = bool(allow_unknown_critical)
        self.allow_ca = bool(allow_ca)


class ExtensionSource(object):
    """
    Describes where within the certification request info a candidate
    extension originated from.
    """

    # The attribute type name, e.g. "extension_request"
    attribute_type = None

    # The 0-based index of the attribute within the CRI attributes
    attribute_index = None

    # The 0-based index of the extension within the attribute's extensions
    extension_index = None

    def __init__(self, attribute_type, attribute_index, extension_index):
        self.attribute_type = attribute_type
        self.attribute_index = attribute_index
        self.extension_index = extension_index

    def __eq__(self, other):
        return (
            isinstance(other, ExtensionSource) and
            self.attribute_type == other.attribute_type and
            self.attribute_index == other.attribute_index and
            self.extension_index == other.extension_index
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return '<%s %s[%d].extensions[%d]>' % (
            self.__class__.__name__,
            self.attribute_type,
            self.attribute_index,
            self.extension_index,
        )


class CandidateExtension(object):
    """
    A single requested extension that passed policy evaluation and may be
    considered by a signing service. This is purely informational - no
    certificate is issued by the evaluation.
    """

    # The dotted OID unicode string of the extension
    oid = None

    # The short name of the extension if known, otherwise the dotted OID
    name = None

    # A bool indicating if the request marked the extension critical
    critical = None

    # The x509.Extension "extn_value" ParsableOctetString - use .parsed for
    # the parsed value
    value = None

    # An ExtensionSource object describing the origin of this extension
    source = None

    def __init__(self, oid, name, critical, value, source):
        self.oid = oid
        self.name = name
        self.critical = critical
        self.value = value
        self.source = source

    def __repr__(self):
        return '<%s %s critical=%s>' % (
            self.__class__.__name__,
            self.oid,
            self.critical,
        )


class CSREvaluationResult(object):
    """
    The read-only outcome of a successful evaluation. Contains no issued
    certificate - only the building blocks a signing service may use.
    """

    # The x509.Name of the requested subject
    subject = None

    # The keys.PublicKeyInfo of the requested subject public key
    public_key = None

    # A list of CandidateExtension objects that passed policy evaluation
    extensions = None

    def __init__(self, subject, public_key, extensions):
        self.subject = subject
        self.public_key = public_key
        self.extensions = extensions


def evaluate_certification_request(certification_request, verify_callback, policy):
    """
    Performs a read-only evaluation of a certification request for a signing
    service. The request is never modified and no certificate is issued.

    The original encoded CertificationRequestInfo bytes, the signature
    algorithm (including parameters) and the signature are handed to
    verify_callback first. Only if the callback confirms the signature are
    the requested attributes and extensions evaluated against the explicit
    policy.

    :param certification_request:
        A CertificationRequest object, or a byte string of DER- or
        PEM-encoded data to load as one

    :param verify_callback:
        A callable that is passed:
          - a byte string of the original encoded CertificationRequestInfo
          - the algos.SignedDigestAlgorithm object (algorithm OID and
            parameters)
          - a byte string of the signature
        It must return a truthy value if the signature is valid for the
        request's public key. Any exception or falsy return value results
        in a CSREvaluationError at the "signature" stage.

    :param policy:
        A CSREvaluationPolicy object

    :raises:
        CSREvaluationError - when the signature can not be verified, when
        attributes are malformed or duplicated, or when requested extensions
        violate the policy. The .stage attribute identifies the stage.

    :return:
        A CSREvaluationResult object
    """

    if isinstance(policy, CSREvaluationPolicy) is not True:
        raise TypeError('policy must be a CSREvaluationPolicy object')

    if isinstance(certification_request, (bytes, str)):
        if _pem_detect(certification_request):
            _, _, certification_request = _pem_unarmor(certification_request)
        certification_request = CertificationRequest.load(certification_request)

    cri = certification_request['certification_request_info']
    signature_algorithm = certification_request['signature_algorithm']
    signature = certification_request['signature'].native

    # Stage 1: the caller verifies the signature over the original encoded
    # CertificationRequestInfo. A failed verification must never produce an
    # issuable result.
    try:
        verified = verify_callback(cri.dump(), signature_algorithm, signature)
    except Exception as e:
        raise CSREvaluationError(
            EVALUATION_STAGE_SIGNATURE,
            'Signature verification callback raised %s' % type(e).__name__
        )
    if not verified:
        raise CSREvaluationError(
            EVALUATION_STAGE_SIGNATURE,
            'Certification request signature verification failed'
        )

    # Stage 2: collect requested extensions from the attributes, rejecting
    # duplicate attributes unless the policy explicitly merges them.
    requested = []
    seen_attribute_types = set()
    for attribute_index, attribute in enumerate(cri['attributes']):
        attribute_type = attribute['type'].native
        if attribute_type in seen_attribute_types and not policy.allow_duplicate_attributes:
            raise CSREvaluationError(
                EVALUATION_STAGE_ATTRIBUTES,
                'Duplicate attribute of type %s' % attribute_type
            )
        seen_attribute_types.add(attribute_type)

        if attribute_type != 'extension_request':
            continue

        extension_index = 0
        for extensions in attribute['values']:
            for extension in extensions:
                requested.append((
                    ExtensionSource(attribute_type, attribute_index, extension_index),
                    extension,
                ))
                extension_index += 1

    # Stage 3: evaluate each requested extension against the explicit policy.
    candidates = []
    seen_extension_oids = set()
    for source, extension in requested:
        oid = extension['extn_id'].dotted
        critical = bool(extension['critical'].native)

        if oid in seen_extension_oids:
            raise CSREvaluationError(
                EVALUATION_STAGE_EXTENSIONS,
                'Duplicate extension OID %s' % oid
            )
        seen_extension_oids.add(oid)

        if oid not in policy.allowed_extensions:
            if critical and not policy.allow_unknown_critical:
                raise CSREvaluationError(
                    EVALUATION_STAGE_EXTENSIONS,
                    'Critical extension %s is not allowed by policy' % oid
                )
            continue

        candidates.append(CandidateExtension(
            oid=oid,
            name=extension['extn_id'].native,
            critical=critical,
            value=extension['extn_value'],
            source=source,
        ))

    _evaluate_basic_constraints_key_usage(candidates, policy)

    return CSREvaluationResult(
        subject=cri['subject'],
        public_key=cri['subject_pk_info'],
        extensions=candidates,
    )


def _evaluate_basic_constraints_key_usage(candidates, policy):
    """
    Checks the combination of basic constraints and key usage candidates for
    consistency, and ensures CA privileges are only considered when the
    policy explicitly allows them.

    :param candidates:
        A list of CandidateExtension objects

    :param policy:
        A CSREvaluationPolicy object

    :raises:
        CSREvaluationError - at the "extensions" stage when the combination
        is inconsistent or CA privileges are not permitted
    """

    basic_constraints = None
    key_usage = None
    for candidate in candidates:
        if candidate.oid == '2.5.29.19':
            basic_constraints = candidate
        elif candidate.oid == '2.5.29.15':
            key_usage = candidate

    ca_requested = False
    if basic_constraints is not None:
        ca_requested = bool(basic_constraints.value.parsed['ca'].native)

    if ca_requested and not policy.allow_ca:
        raise CSREvaluationError(
            EVALUATION_STAGE_EXTENSIONS,
            'Basic constraints CA:TRUE is not permitted by policy'
        )

    if key_usage is None:
        return

    key_usage_names = set(key_usage.value.parsed.native)
    ca_usages = key_usage_names & set(['key_cert_sign', 'crl_sign'])

    if ca_usages and not ca_requested:
        raise CSREvaluationError(
            EVALUATION_STAGE_EXTENSIONS,
            'Key usage %s requires basic constraints CA:TRUE' %
            sorted(ca_usages)[0]
        )

    if ca_requested and 'key_cert_sign' not in key_usage_names:
        raise CSREvaluationError(
            EVALUATION_STAGE_EXTENSIONS,
            'Basic constraints CA:TRUE requires key usage key_cert_sign'
        )
