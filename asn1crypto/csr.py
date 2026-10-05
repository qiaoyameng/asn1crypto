# coding: utf-8

"""
ASN.1 type classes for certificate signing requests (CSR). Exports the
following items:

 - CertificationRequest()
 - CSREvaluationError()
 - CSRExtensionCandidate()
 - CSREvaluationResult()
 - evaluate_certification_request()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
from ._types import byte_cls, str_cls, type_name
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
from .x509 import DirectoryString, Extensions, Name


class CSREvaluationError(ValueError):
    pass


def _raise_evaluation_error(message):
    error = CSREvaluationError(message)
    error.__suppress_context__ = True
    raise error


class CSRExtensionCandidate(object):
    def __init__(self, extension, source):
        self.extension = extension
        self.source = source


class CSREvaluationResult(object):
    def __init__(self, certification_request, extension_candidates):
        self.certification_request = certification_request
        self.extension_candidates = extension_candidates


def _clean_policy_oids(oids, parameter_name):
    output = set()
    if oids is None:
        return output

    if isinstance(oids, (str_cls, byte_cls)):
        raise TypeError(unwrap(
            '''
            %s must be a list, tuple or set of unicode strings, not a single
            string
            ''',
            parameter_name
        ))

    for oid in oids:
        if not isinstance(oid, str_cls):
            raise TypeError(unwrap(
                '''
                %s must contain unicode strings, not %s
                ''',
                parameter_name,
                type_name(oid)
            ))
        output.add(oid)

    return output


def _evaluate_extensions(extension_candidates, policy):
    allowed_extensions = policy['allowed_extensions']
    allow_unknown_critical = policy['allow_unknown_critical']
    allow_ca = policy['allow_ca']
    duplicate_extensions = policy['duplicate_extensions']

    known_oids = set()
    selected = []
    basic_constraints_ca = None
    key_usage = None

    for candidate in extension_candidates:
        extension = candidate.extension
        oid = extension['extn_id'].dotted
        name = extension['extn_id'].native

        if oid in known_oids:
            if duplicate_extensions == 'reject':
                raise CSREvaluationError(
                    'Duplicate extension OID in extension request: %s' % oid
                )
            if duplicate_extensions == 'use_first':
                continue
            selected = [
                item for item in selected
                if item.extension['extn_id'].dotted != oid
            ]
        known_oids.add(oid)
        selected.append(candidate)

        if name not in allowed_extensions and oid not in allowed_extensions:
            raise CSREvaluationError(
                'Extension OID is not allowed by issuance policy: %s' % oid
            )

        if extension['critical'].native and oid == name:
            if not allow_unknown_critical:
                raise CSREvaluationError(
                    'Unknown critical extension is not allowed: %s' % oid
                )

        if oid == '2.5.29.19':
            constraints = extension['extn_value'].parsed
            basic_constraints_ca = constraints['ca'].native
            if (
                not constraints['ca'].native and
                constraints['path_len_constraint'].native is not None
            ):
                raise CSREvaluationError(
                    'Path length constraint is not valid without CA'
                )
            if constraints['ca'].native and not allow_ca:
                raise CSREvaluationError(
                    'Request for CA basic constraints is not allowed'
                )

        if oid == '2.5.29.15':
            key_usage = extension['extn_value'].parsed.native

    if key_usage is not None:
        requests_ca_usage = 'key_cert_sign' in key_usage or 'crl_sign' in key_usage
        if requests_ca_usage and not allow_ca:
            raise CSREvaluationError(
                'Request for CA key usage is not allowed'
            )
        if basic_constraints_ca is True and 'key_cert_sign' not in key_usage:
            raise CSREvaluationError(
                'CA basic constraints require keyCertSign in key usage'
            )
        if basic_constraints_ca is False and requests_ca_usage:
            raise CSREvaluationError(
                'CA key usage conflicts with non-CA basic constraints'
            )

    return selected


def evaluate_certification_request(
        certification_request,
        verify_signature,
        allowed_extensions,
        duplicate_attributes='reject',
        duplicate_extensions='reject',
        allow_unknown_critical=False,
        allow_ca=False):
    """
    Verifies a CSR and returns its requested extensions without issuing one

    :param certification_request:
        A byte string or CertificationRequest object

    :param verify_signature:
        A callable invoked as
        ``verify_signature(certification_request_info, signature_algorithm,
        signature, subject_public_key_info)``. It must return True only when
        the CSR signature is valid.

    :param allowed_extensions:
        A list, tuple or set of extension names and/or dotted OIDs

    :param duplicate_attributes:
        A unicode string of "reject", "use_first" or "use_last"

    :param duplicate_extensions:
        A unicode string of "reject", "use_first" or "use_last"

    :param allow_unknown_critical:
        A boolean - if unknown critical extensions may be returned

    :param allow_ca:
        A boolean - if CA basic constraints and CA key usage may be returned

    :raises:
        CSREvaluationError - when the callback rejects the CSR or policy fails

    :return:
        A CSREvaluationResult object
    """

    if not callable(verify_signature):
        raise TypeError(unwrap(
            '''
            verify_signature must be callable, not %s
            ''',
            type_name(verify_signature)
        ))

    if isinstance(certification_request, byte_cls):
        try:
            certification_request = CertificationRequest.load(certification_request)
        except (ValueError, TypeError):
            _raise_evaluation_error('CSR is malformed')

    if not isinstance(certification_request, CertificationRequest):
        raise TypeError(unwrap(
            '''
            certification_request must be a byte string or CertificationRequest,
            not %s
            ''',
            type_name(certification_request)
        ))

    choices = ('reject', 'use_first', 'use_last')
    if duplicate_attributes not in choices:
        raise ValueError('duplicate_attributes must be one of %s' % repr(choices))
    if duplicate_extensions not in choices:
        raise ValueError('duplicate_extensions must be one of %s' % repr(choices))

    allowed_extensions = _clean_policy_oids(
        allowed_extensions,
        'allowed_extensions'
    )

    try:
        cri = certification_request['certification_request_info']
        signature_algorithm = certification_request['signature_algorithm']
        signature = certification_request['signature'].native
        certification_request_info = cri.dump()
        subject_public_key_info = cri['subject_pk_info']
    except Exception:
        _raise_evaluation_error('CSR is malformed')

    try:
        valid = verify_signature(
            certification_request_info,
            signature_algorithm,
            signature,
            subject_public_key_info
        )
    except Exception:
        _raise_evaluation_error('CSR signature verification failed')

    if valid is not True:
        _raise_evaluation_error('CSR signature verification failed')

    extension_candidates = []
    extension_request_indices = []
    try:
        try:
            attributes = cri['attributes']
        except KeyError:
            attributes = []

        for attribute_index, attribute in enumerate(attributes):
            if attribute['type'].dotted != '1.2.840.113549.1.9.14':
                continue

            extension_request_indices.append(attribute_index)
            values = attribute['values']
            if len(values) != 1:
                raise CSREvaluationError(
                    'extensionRequest attribute must contain exactly one value'
                )

            extensions = values[0]
            for extension_index, extension in enumerate(extensions):
                extension_candidates.append(CSRExtensionCandidate(
                    extension,
                    {
                        'attribute_index': attribute_index,
                        'attribute_occurrence': len(extension_request_indices),
                        'extension_index': extension_index,
                    }
                ))

        if len(extension_request_indices) > 1:
            if duplicate_attributes == 'reject':
                raise CSREvaluationError(
                    'Duplicate extensionRequest attribute is not allowed'
                )
            if duplicate_attributes == 'use_first':
                keep_index = extension_request_indices[0]
            else:
                keep_index = extension_request_indices[-1]
            extension_candidates = [
                candidate for candidate in extension_candidates
                if candidate.source['attribute_index'] == keep_index
            ]

        extension_candidates = _evaluate_extensions(extension_candidates, {
            'allowed_extensions': allowed_extensions,
            'allow_unknown_critical': allow_unknown_critical,
            'allow_ca': allow_ca,
            'duplicate_extensions': duplicate_extensions,
        })
    except CSREvaluationError:
        raise
    except (ValueError, TypeError, KeyError, IndexError):
        _raise_evaluation_error('CSR extension request is malformed')

    return CSREvaluationResult(certification_request, extension_candidates)


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
