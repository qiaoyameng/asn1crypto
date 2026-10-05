# coding: utf-8

"""
ASN.1 type classes for the online certificate status protocol (OCSP). Exports
the following items:

- OCSPRequest()
- OCSPResponse()
- check_ocsp_response()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
from datetime import datetime, timedelta

from ._errors import unwrap
from ._types import byte_cls, type_name
from .algos import DigestAlgorithm, SignedDigestAlgorithm
from .core import (
    Boolean,
    Choice,
    Enumerated,
    GeneralizedTime,
    IA5String,
    Integer,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
)
from .crl import AuthorityInfoAccessSyntax, CRLReason
from .keys import PublicKeyAlgorithm
from .pem import detect as _pem_detect, unarmor as _pem_unarmor
from .util import timezone
from .x509 import Certificate, GeneralName, GeneralNames, Name


OCSP_STATUSES = frozenset([
    'good',
    'revoked',
    'unknown',
    'expired',
    'no_match',
    'invalid',
    'unauthorized',
    'unsuccessful',
])

NONCE_POLICIES = frozenset([
    'optional',
    'required',
    'ignore',
])


# The structures in this file are taken from https://tools.ietf.org/html/rfc6960


class Version(Integer):
    _map = {
        0: 'v1'
    }


class CertId(Sequence):
    _fields = [
        ('hash_algorithm', DigestAlgorithm),
        ('issuer_name_hash', OctetString),
        ('issuer_key_hash', OctetString),
        ('serial_number', Integer),
    ]


class ServiceLocator(Sequence):
    _fields = [
        ('issuer', Name),
        ('locator', AuthorityInfoAccessSyntax),
    ]


class RequestExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.7': 'service_locator',
    }


class RequestExtension(Sequence):
    _fields = [
        ('extn_id', RequestExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', ParsableOctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'service_locator': ServiceLocator,
    }


class RequestExtensions(SequenceOf):
    _child_spec = RequestExtension


class Request(Sequence):
    _fields = [
        ('req_cert', CertId),
        ('single_request_extensions', RequestExtensions, {'explicit': 0, 'optional': True}),
    ]

    _processed_extensions = False
    _critical_extensions = None
    _service_locator_value = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = set()

        for extension in self['single_request_extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.add(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a set of the names (or OID if not a known extension) of the
        extensions marked as critical

        :return:
            A set of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def service_locator_value(self):
        """
        This extension is used when communicating with an OCSP responder that
        acts as a proxy for OCSP requests

        :return:
            None or a ServiceLocator object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._service_locator_value


class Requests(SequenceOf):
    _child_spec = Request


class ResponseType(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.1': 'basic_ocsp_response',
    }


class AcceptableResponses(SequenceOf):
    _child_spec = ResponseType


class PreferredSignatureAlgorithm(Sequence):
    _fields = [
        ('sig_identifier', SignedDigestAlgorithm),
        ('cert_identifier', PublicKeyAlgorithm, {'optional': True}),
    ]


class PreferredSignatureAlgorithms(SequenceOf):
    _child_spec = PreferredSignatureAlgorithm


class TBSRequestExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.2': 'nonce',
        '1.3.6.1.5.5.7.48.1.4': 'acceptable_responses',
        '1.3.6.1.5.5.7.48.1.8': 'preferred_signature_algorithms',
    }


class TBSRequestExtension(Sequence):
    _fields = [
        ('extn_id', TBSRequestExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', ParsableOctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'nonce': OctetString,
        'acceptable_responses': AcceptableResponses,
        'preferred_signature_algorithms': PreferredSignatureAlgorithms,
    }


class TBSRequestExtensions(SequenceOf):
    _child_spec = TBSRequestExtension


class TBSRequest(Sequence):
    _fields = [
        ('version', Version, {'explicit': 0, 'default': 'v1'}),
        ('requestor_name', GeneralName, {'explicit': 1, 'optional': True}),
        ('request_list', Requests),
        ('request_extensions', TBSRequestExtensions, {'explicit': 2, 'optional': True}),
    ]


class Certificates(SequenceOf):
    _child_spec = Certificate


class Signature(Sequence):
    _fields = [
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
        ('certs', Certificates, {'explicit': 0, 'optional': True}),
    ]


class OCSPRequest(Sequence):
    _fields = [
        ('tbs_request', TBSRequest),
        ('optional_signature', Signature, {'explicit': 0, 'optional': True}),
    ]

    _processed_extensions = False
    _critical_extensions = None
    _nonce_value = None
    _acceptable_responses_value = None
    _preferred_signature_algorithms_value = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = set()

        for extension in self['tbs_request']['request_extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.add(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a set of the names (or OID if not a known extension) of the
        extensions marked as critical

        :return:
            A set of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def nonce_value(self):
        """
        This extension is used to prevent replay attacks by including a unique,
        random value with each request/response pair

        :return:
            None or an OctetString object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._nonce_value

    @property
    def acceptable_responses_value(self):
        """
        This extension is used to allow the client and server to communicate
        with alternative response formats other than just basic_ocsp_response,
        although no other formats are defined in the standard.

        :return:
            None or an AcceptableResponses object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._acceptable_responses_value

    @property
    def preferred_signature_algorithms_value(self):
        """
        This extension is used by the client to define what signature algorithms
        are preferred, including both the hash algorithm and the public key
        algorithm, with a level of detail down to even the public key algorithm
        parameters, such as curve name.

        :return:
            None or a PreferredSignatureAlgorithms object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._preferred_signature_algorithms_value


class OCSPResponseStatus(Enumerated):
    _map = {
        0: 'successful',
        1: 'malformed_request',
        2: 'internal_error',
        3: 'try_later',
        5: 'sign_required',
        6: 'unauthorized',
    }


class ResponderId(Choice):
    _alternatives = [
        ('by_name', Name, {'explicit': 1}),
        ('by_key', OctetString, {'explicit': 2}),
    ]


# Custom class to return a meaningful .native attribute from CertStatus()
class StatusGood(Null):
    def set(self, value):
        """
        Sets the value of the object

        :param value:
            None or 'good'
        """

        if value is not None and value != 'good' and not isinstance(value, Null):
            raise ValueError(unwrap(
                '''
                value must be one of None, "good", not %s
                ''',
                repr(value)
            ))

        self.contents = b''

    @property
    def native(self):
        return 'good'


# Custom class to return a meaningful .native attribute from CertStatus()
class StatusUnknown(Null):
    def set(self, value):
        """
        Sets the value of the object

        :param value:
            None or 'unknown'
        """

        if value is not None and value != 'unknown' and not isinstance(value, Null):
            raise ValueError(unwrap(
                '''
                value must be one of None, "unknown", not %s
                ''',
                repr(value)
            ))

        self.contents = b''

    @property
    def native(self):
        return 'unknown'


class RevokedInfo(Sequence):
    _fields = [
        ('revocation_time', GeneralizedTime),
        ('revocation_reason', CRLReason, {'explicit': 0, 'optional': True}),
    ]


class CertStatus(Choice):
    _alternatives = [
        ('good', StatusGood, {'implicit': 0}),
        ('revoked', RevokedInfo, {'implicit': 1}),
        ('unknown', StatusUnknown, {'implicit': 2}),
    ]


class CrlId(Sequence):
    _fields = [
        ('crl_url', IA5String, {'explicit': 0, 'optional': True}),
        ('crl_num', Integer, {'explicit': 1, 'optional': True}),
        ('crl_time', GeneralizedTime, {'explicit': 2, 'optional': True}),
    ]


class SingleResponseExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.3': 'crl',
        '1.3.6.1.5.5.7.48.1.6': 'archive_cutoff',
        # These are CRLEntryExtension values from
        # https://tools.ietf.org/html/rfc5280
        '2.5.29.21': 'crl_reason',
        '2.5.29.24': 'invalidity_date',
        '2.5.29.29': 'certificate_issuer',
        # https://tools.ietf.org/html/rfc6962.html#page-13
        '1.3.6.1.4.1.11129.2.4.5': 'signed_certificate_timestamp_list',
    }


class SingleResponseExtension(Sequence):
    _fields = [
        ('extn_id', SingleResponseExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', ParsableOctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'crl': CrlId,
        'archive_cutoff': GeneralizedTime,
        'crl_reason': CRLReason,
        'invalidity_date': GeneralizedTime,
        'certificate_issuer': GeneralNames,
        'signed_certificate_timestamp_list': OctetString,
    }


class SingleResponseExtensions(SequenceOf):
    _child_spec = SingleResponseExtension


class SingleResponse(Sequence):
    _fields = [
        ('cert_id', CertId),
        ('cert_status', CertStatus),
        ('this_update', GeneralizedTime),
        ('next_update', GeneralizedTime, {'explicit': 0, 'optional': True}),
        ('single_extensions', SingleResponseExtensions, {'explicit': 1, 'optional': True}),
    ]

    _processed_extensions = False
    _critical_extensions = None
    _crl_value = None
    _archive_cutoff_value = None
    _crl_reason_value = None
    _invalidity_date_value = None
    _certificate_issuer_value = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = set()

        for extension in self['single_extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.add(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a set of the names (or OID if not a known extension) of the
        extensions marked as critical

        :return:
            A set of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def crl_value(self):
        """
        This extension is used to locate the CRL that a certificate's revocation
        is contained within.

        :return:
            None or a CrlId object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._crl_value

    @property
    def archive_cutoff_value(self):
        """
        This extension is used to indicate the date at which an archived
        (historical) certificate status entry will no longer be available.

        :return:
            None or a GeneralizedTime object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._archive_cutoff_value

    @property
    def crl_reason_value(self):
        """
        This extension indicates the reason that a certificate was revoked.

        :return:
            None or a CRLReason object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._crl_reason_value

    @property
    def invalidity_date_value(self):
        """
        This extension indicates the suspected date/time the private key was
        compromised or the certificate became invalid. This would usually be
        before the revocation date, which is when the CA processed the
        revocation.

        :return:
            None or a GeneralizedTime object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._invalidity_date_value

    @property
    def certificate_issuer_value(self):
        """
        This extension indicates the issuer of the certificate in question.

        :return:
            None or an x509.GeneralNames object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._certificate_issuer_value


class Responses(SequenceOf):
    _child_spec = SingleResponse


class ResponseDataExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.2': 'nonce',
        '1.3.6.1.5.5.7.48.1.9': 'extended_revoke',
    }


class ResponseDataExtension(Sequence):
    _fields = [
        ('extn_id', ResponseDataExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', ParsableOctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'nonce': OctetString,
        'extended_revoke': Null,
    }


class ResponseDataExtensions(SequenceOf):
    _child_spec = ResponseDataExtension


class ResponseData(Sequence):
    _fields = [
        ('version', Version, {'explicit': 0, 'default': 'v1'}),
        ('responder_id', ResponderId),
        ('produced_at', GeneralizedTime),
        ('responses', Responses),
        ('response_extensions', ResponseDataExtensions, {'explicit': 1, 'optional': True}),
    ]


class BasicOCSPResponse(Sequence):
    _fields = [
        ('tbs_response_data', ResponseData),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
        ('certs', Certificates, {'explicit': 0, 'optional': True}),
    ]


class ResponseBytes(Sequence):
    _fields = [
        ('response_type', ResponseType),
        ('response', ParsableOctetString),
    ]

    _oid_pair = ('response_type', 'response')
    _oid_specs = {
        'basic_ocsp_response': BasicOCSPResponse,
    }


class OCSPResponse(Sequence):
    _fields = [
        ('response_status', OCSPResponseStatus),
        ('response_bytes', ResponseBytes, {'explicit': 0, 'optional': True}),
    ]

    _processed_extensions = False
    _critical_extensions = None
    _nonce_value = None
    _extended_revoke_value = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = set()

        for extension in self['response_bytes']['response'].parsed['tbs_response_data']['response_extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.add(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a set of the names (or OID if not a known extension) of the
        extensions marked as critical

        :return:
            A set of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def nonce_value(self):
        """
        This extension is used to prevent replay attacks on the request/response
        exchange

        :return:
            None or an OctetString object
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._nonce_value

    @property
    def extended_revoke_value(self):
        """
        This extension is used to signal that the responder will return a
        "revoked" status for non-issued certificates.

        :return:
            None or a Null object (if present)
        """

        if self._processed_extensions is False:
            self._set_extensions()
        return self._extended_revoke_value

    @property
    def basic_ocsp_response(self):
        """
        A shortcut into the BasicOCSPResponse sequence

        :return:
            None or an asn1crypto.ocsp.BasicOCSPResponse object
        """

        return self['response_bytes']['response'].parsed

    @property
    def response_data(self):
        """
        A shortcut into the parsed, ResponseData sequence

        :return:
            None or an asn1crypto.ocsp.ResponseData object
        """

        return self['response_bytes']['response'].parsed['tbs_response_data']


class OCSPResponseAssessment(object):
    """
    The result of correlating and assessing an OCSP response for one cert.
    """

    __slots__ = [
        'status',
        'reason',
        'trusted',
        'cert_status',
        'revocation_time',
        'revocation_reason',
        'this_update',
        'next_update',
        'produced_at',
        'single_response',
        'basic_ocsp_response',
    ]

    def __init__(self, status, reason=None, trusted=False, cert_status=None,
                 revocation_time=None, revocation_reason=None, this_update=None,
                 next_update=None, produced_at=None, single_response=None,
                 basic_ocsp_response=None):
        self.status = status
        self.reason = reason
        self.trusted = trusted
        self.cert_status = cert_status
        self.revocation_time = revocation_time
        self.revocation_reason = revocation_reason
        self.this_update = this_update
        self.next_update = next_update
        self.produced_at = produced_at
        self.single_response = single_response
        self.basic_ocsp_response = basic_ocsp_response

    @property
    def trusted_good(self):
        return self.trusted and self.status == 'good'

    def __getitem__(self, key):
        return getattr(self, key)

    def __contains__(self, key):
        return hasattr(self, key)

    def __iter__(self):
        return iter(self.__slots__ + ['trusted_good'])

    def __repr__(self):
        return 'OCSPResponseAssessment(%s)' % self.as_native()

    def as_native(self):
        result = {}
        for key in self:
            value = getattr(self, key)
            if isinstance(value, (OCSPResponse, BasicOCSPResponse, SingleResponse)):
                value = value.dump()
            result[key] = value
        return result


def _certificate(value):
    if isinstance(value, Certificate):
        return value
    if isinstance(value, byte_cls):
        if _pem_detect(value):
            value = _pem_unarmor(value)[2]
        return Certificate.load(value)
    raise TypeError(unwrap(
        '''
        certificate must be an asn1crypto.x509.Certificate object or byte
        string, not %s
        ''',
        type_name(value)
    ))


def _request(value):
    if isinstance(value, OCSPRequest):
        return value
    if isinstance(value, byte_cls):
        return OCSPRequest.load(value)
    raise TypeError(unwrap(
        '''
        request must be an asn1crypto.ocsp.OCSPRequest object or byte string,
        not %s
        ''',
        type_name(value)
    ))


def _response(value):
    if isinstance(value, OCSPResponse):
        return value
    if isinstance(value, byte_cls):
        return OCSPResponse.load(value)
    raise TypeError(unwrap(
        '''
        response must be an asn1crypto.ocsp.OCSPResponse object or byte string,
        not %s
        ''',
        type_name(value)
    ))


def _aware_time(value, name):
    if not isinstance(value, datetime):
        raise TypeError(unwrap(
            '''
            %s must be a datetime.datetime object, not %s
            ''',
            name,
            type_name(value)
        ))
    if value.tzinfo is None:
        raise ValueError('%s must be timezone-aware' % name)
    return value.astimezone(timezone.utc)


def _timedelta(value, name, allow_none=False):
    if value is None and allow_none:
        return None
    if not isinstance(value, timedelta):
        raise TypeError(unwrap(
            '''
            %s must be a datetime.timedelta object, not %s
            ''',
            name,
            type_name(value)
        ))
    if value < timedelta(0):
        raise ValueError('%s must not be negative' % name)
    return value


def _nonce(extensions):
    if extensions is None:
        return None, False
    values = []
    for extension in extensions:
        if extension['extn_id'].native == 'nonce':
            values.append(extension['extn_value'].parsed.native)
    if not values:
        return None, False
    return values[0], any(value != values[0] for value in values[1:])


def _critical_extensions(extensions):
    if extensions is None:
        return set()
    result = set()
    for extension in extensions:
        if extension['critical'].native:
            result.add(extension['extn_id'].native)
    return result


def _cert_id_matches(cert_id, target_certificate, issuer_certificate):
    algorithm = cert_id['hash_algorithm']['algorithm'].native
    try:
        digest = hashlib.new(algorithm)
    except (ValueError, TypeError):
        raise ValueError(
            'OCSP CertID uses unsupported hash algorithm %r' % algorithm
        )

    digest.update(issuer_certificate.subject.dump())
    expected_name_hash = digest.digest()
    digest = hashlib.new(algorithm)
    digest.update(issuer_certificate.public_key['public_key'].contents)
    expected_key_hash = digest.digest()

    return (
        cert_id['serial_number'].native == target_certificate.serial_number and
        cert_id['issuer_name_hash'].native == expected_name_hash and
        cert_id['issuer_key_hash'].native == expected_key_hash
    )


def _certificate_issuer_matches(single_response, issuer_certificate):
    certificate_issuer = single_response.certificate_issuer_value
    if certificate_issuer is None:
        return True
    issuer_name = issuer_certificate.subject.dump()
    for name in certificate_issuer:
        if name.name == 'directory_name' and name.chosen.dump() == issuer_name:
            return True
    return False


def _single_response_identity(single_response):
    cert_status = single_response['cert_status']
    status_name = cert_status.name
    extensions = single_response['single_extensions']
    extensions_encoding = extensions.dump() if extensions.native is not None else None
    if status_name == 'revoked':
        status_value = cert_status.chosen.dump()
    else:
        status_value = b''
    return (
        status_name,
        status_value,
        single_response['this_update'].native,
        single_response['next_update'].native,
        extensions_encoding,
    )


def check_ocsp_response(target_certificate, issuer_certificate, request, response,
                        evaluation_time, responder_verifier,
                        clock_skew=timedelta(0), max_age=None,
                        nonce_policy='optional', **kwargs):
    """
    Correlate an OCSP response with the request/certificate and assess it.

    responder_verifier is called as responder_verifier(basic_ocsp_response,
    target_certificate, issuer_certificate) once a matching, timely response is
    found. It must return a truthy value; an exception or false result prevents
    any "good" result.
    """

    for key in ('allowed_skew', 'allowed_clock_skew', 'skew', 'tolerance'):
        if key in kwargs:
            clock_skew = kwargs.pop(key)
    for key in ('response_age_limit', 'age_limit', 'stale_age_limit'):
        if key in kwargs:
            max_age = kwargs.pop(key)
    for key in ('nonce_strategy', 'nonce_mode'):
        if key in kwargs:
            nonce_policy = kwargs.pop(key)
    if kwargs:
        raise TypeError(
            'unsupported keyword arguments: %s' % ', '.join(sorted(kwargs))
        )

    target_certificate = _certificate(target_certificate)
    issuer_certificate = _certificate(issuer_certificate)
    request = _request(request)
    response = _response(response)
    evaluation_time = _aware_time(evaluation_time, 'evaluation_time')
    clock_skew = _timedelta(clock_skew, 'clock_skew')
    max_age = _timedelta(max_age, 'max_age', allow_none=True)
    if nonce_policy not in NONCE_POLICIES:
        raise ValueError(
            'nonce_policy must be one of %s' % ', '.join(sorted(NONCE_POLICIES))
        )
    if not callable(responder_verifier):
        raise TypeError('responder_verifier must be callable')

    if response['response_status'].native != 'successful':
        return OCSPResponseAssessment(
            'unsuccessful',
            response['response_status'].native
        )

    try:
        response_bytes = response['response_bytes']
        if response_bytes.native is None:
            return OCSPResponseAssessment('invalid', 'missing_response_bytes')
        response_type = response_bytes['response_type'].native
    except (TypeError, ValueError, KeyError, IndexError):
        return OCSPResponseAssessment('invalid', 'malformed_response_bytes')

    if response_type != 'basic_ocsp_response':
        return OCSPResponseAssessment('invalid', 'unsupported_response_type')

    try:
        basic_response = response.basic_ocsp_response
        response_data = basic_response['tbs_response_data']
        produced_at = response_data['produced_at'].native
        responses = response_data['responses']
        if not len(responses):
            return OCSPResponseAssessment('invalid', 'empty_responses')
    except (TypeError, ValueError, KeyError, IndexError):
        return OCSPResponseAssessment('invalid', 'malformed_response')

    try:
        request_nonce, duplicate_request_nonce = _nonce(
            request['tbs_request']['request_extensions']
        )
        response_nonce, duplicate_response_nonce = _nonce(
            response_data['response_extensions']
        )
        unsupported_response_extensions = _critical_extensions(
            response_data['response_extensions']
        ) - set(['nonce', 'extended_revoke'])
    except (TypeError, ValueError, KeyError, IndexError):
        return OCSPResponseAssessment('invalid', 'malformed_extensions')
    if duplicate_request_nonce or duplicate_response_nonce:
        return OCSPResponseAssessment('invalid', 'duplicate_nonce')
    if unsupported_response_extensions:
        return OCSPResponseAssessment('invalid', 'unsupported_critical_extension')

    if nonce_policy != 'ignore':
        if nonce_policy == 'required' and request_nonce is None:
            return OCSPResponseAssessment('invalid', 'request_nonce_required')
        if request_nonce is not None and response_nonce != request_nonce:
            return OCSPResponseAssessment('no_match', 'nonce_mismatch')
        if nonce_policy == 'required' and response_nonce is None:
            return OCSPResponseAssessment('no_match', 'nonce_missing')

    request_cert_ids = []
    try:
        for single_request in request['tbs_request']['request_list']:
            cert_id = single_request['req_cert']
            if cert_id.dump() in [existing.dump() for existing in request_cert_ids]:
                continue
            request_cert_ids.append(cert_id)
    except (TypeError, ValueError, KeyError, IndexError):
        return OCSPResponseAssessment('invalid', 'malformed_request')

    matches = []
    supported_single_response_extensions = set([
        'crl',
        'archive_cutoff',
        'crl_reason',
        'invalidity_date',
        'certificate_issuer',
        'signed_certificate_timestamp_list',
    ])
    for single_response in responses:
        try:
            cert_id = single_response['cert_id']
            in_request = any(
                cert_id.dump() == request_cert_id.dump()
                for request_cert_id in request_cert_ids
            )
            matches_certificate = _cert_id_matches(
                cert_id, target_certificate, issuer_certificate
            )
            issuer_matches = _certificate_issuer_matches(
                single_response, issuer_certificate
            )
            unsupported_single_extensions = _critical_extensions(
                single_response['single_extensions']
            ) - supported_single_response_extensions
        except (TypeError, ValueError, KeyError, IndexError):
            return OCSPResponseAssessment('invalid', 'malformed_cert_id')

        if not (in_request and matches_certificate and issuer_matches):
            continue

        if unsupported_single_extensions:
            return OCSPResponseAssessment(
                'invalid',
                'unsupported_critical_extension'
            )

        matches.append(single_response)

    if not matches:
        return OCSPResponseAssessment('no_match', 'no_matching_cert_id')

    identities = set()
    for single_response in matches:
        try:
            identities.add(_single_response_identity(single_response))
        except (TypeError, ValueError, KeyError, IndexError):
            return OCSPResponseAssessment('invalid', 'malformed_single_response')
    if len(identities) != 1:
        return OCSPResponseAssessment('invalid', 'contradictory_single_responses')

    match = matches[0]
    this_update = match['this_update'].native
    next_update = match['next_update'].native

    if this_update.tzinfo is None or produced_at.tzinfo is None:
        return OCSPResponseAssessment('invalid', 'malformed_response_time')

    if produced_at > evaluation_time + clock_skew:
        return OCSPResponseAssessment('invalid', 'response_from_future')
    if this_update > produced_at + clock_skew:
        return OCSPResponseAssessment('invalid', 'this_update_after_produced_at')
    if this_update > evaluation_time + clock_skew:
        return OCSPResponseAssessment('invalid', 'status_not_yet_valid')

    if next_update is not None:
        if next_update < this_update:
            return OCSPResponseAssessment('invalid', 'next_update_before_this_update')
        fresh_until = next_update
    else:
        if max_age is None:
            return OCSPResponseAssessment('expired', 'no_next_update_and_no_max_age')
        fresh_until = this_update + max_age

    if evaluation_time > fresh_until + clock_skew:
        return OCSPResponseAssessment('expired', 'next_update_exceeded')

    try:
        authorized = responder_verifier(basic_response, target_certificate, issuer_certificate)
    except Exception as verifier_error:
        return OCSPResponseAssessment(
            'unauthorized',
            'responder_verifier_error: %s' % verifier_error,
            produced_at=produced_at,
            this_update=this_update,
            next_update=next_update,
            single_response=match,
            basic_ocsp_response=basic_response
        )

    if not authorized:
        return OCSPResponseAssessment(
            'unauthorized',
            'responder_not_authorized',
            produced_at=produced_at,
            this_update=this_update,
            next_update=next_update,
            single_response=match,
            basic_ocsp_response=basic_response
        )

    revocation_time = None
    revocation_reason = None
    try:
        cert_status = match['cert_status']
        status_name = cert_status.name
        if status_name == 'revoked':
            revocation_time = cert_status.chosen['revocation_time'].native
            if match.crl_reason_value is not None:
                revocation_reason = match.crl_reason_value.native
    except (TypeError, ValueError, KeyError, IndexError):
        return OCSPResponseAssessment(
            'invalid',
            'malformed_cert_status',
            produced_at=produced_at,
            this_update=this_update,
            next_update=next_update,
            single_response=match,
            basic_ocsp_response=basic_response
        )

    return OCSPResponseAssessment(
        status_name,
        trusted=True,
        cert_status=status_name,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
        this_update=this_update,
        next_update=next_update,
        produced_at=produced_at,
        single_response=match,
        basic_ocsp_response=basic_response
    )


class OCSPResponseChecker(object):
    def __init__(self, **kwargs):
        self.options = kwargs

    def check(self, target_certificate, issuer_certificate, request, response,
              evaluation_time, responder_verifier, **kwargs):
        options = self.options.copy()
        options.update(kwargs)
        return check_ocsp_response(
            target_certificate,
            issuer_certificate,
            request,
            response,
            evaluation_time,
            responder_verifier,
            **options
        )

    def assess(self, *args, **kwargs):
        return self.check(*args, **kwargs)

    def validate(self, *args, **kwargs):
        return self.check(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.check(*args, **kwargs)


class OCSPResponseValidator(object):
    def __init__(self, **kwargs):
        self.options = kwargs

    def validate(self, *args, **kwargs):
        options = self.options.copy()
        options.update(kwargs)
        return check_ocsp_response(*args, **options)

    def check(self, *args, **kwargs):
        return self.validate(*args, **kwargs)

    def assess(self, *args, **kwargs):
        return self.validate(*args, **kwargs)


def assess_ocsp_response(*args, **kwargs):
    return check_ocsp_response(*args, **kwargs)


def validate_ocsp_response(*args, **kwargs):
    return check_ocsp_response(*args, **kwargs)
