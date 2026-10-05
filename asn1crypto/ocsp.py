# coding: utf-8

"""
ASN.1 type classes for the online certificate status protocol (OCSP). Exports
the following items:

 - OCSPRequest()
 - OCSPResponse()
 - OCSPResponseStatusError()
 - OCSPResponseAssociationError()
 - assess_ocsp_response()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
from datetime import datetime, timedelta

from ._errors import unwrap
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
from ._types import byte_cls
from .util import timezone
from .x509 import Certificate, GeneralName, GeneralNames, Name


class OCSPResponseStatusError(Exception):
    """
    An exception indicating an OCSP response can not be associated with a
    status for the certificate in question - for example when the response
    itself indicates an error, was generated for a different request, or is
    malformed in some way
    """

    pass


class OCSPResponseAssociationError(OCSPResponseStatusError):
    """
    An exception indicating an OCSP response was not produced in answer to the
    request for the target certificate - for example due to mismatched
    CertIDs, nonce policy violations or contradictory SingleResponses
    """

    pass


# Nonce policies accepted by assess_ocsp_response()
NONCE_IGNORE = 'ignore'
NONCE_MATCH_IF_SENT = 'match_if_sent'
NONCE_REQUIRE = 'require'

_NONCE_POLICIES = frozenset([NONCE_IGNORE, NONCE_MATCH_IF_SENT, NONCE_REQUIRE])


# Assessment outcomes returned by assess_ocsp_response()
STATUS_GOOD = 'good'
STATUS_REVOKED = 'revoked'
STATUS_UNKNOWN = 'unknown'
STATUS_EXPIRED = 'expired'
STATUS_NO_MATCH = 'no_match'


class OCSPResponseAssessment(object):
    """
    The result of correlating an OCSPResponse() with a target certificate and
    the original request via assess_ocsp_response()

    :ivar status:
        A unicode string of "good", "revoked", "unknown", "expired" or
        "no_match"

    :ivar trusted:
        A boolean - True only when the responder_signature_callback() confirmed
        both that the BasicOCSPResponse signature is valid and that the
        responder is authorized to answer for the issuer. A "good" assessment
        is never returned when trusted is False

    :ivar revocation_time:
        None, or an aware datetime of when the certificate was revoked

    :ivar revocation_reason:
        None, or a unicode string of the CRL revocation reason

    :ivar this_update:
        None, or the matched SingleResponse thisUpdate as an aware datetime

    :ivar next_update:
        None, or the matched SingleResponse nextUpdate as an aware datetime

    :ivar produced_at:
        None, or the BasicOCSPResponse producedAt as an aware datetime

    :ivar single_response:
        None, or the matched SingleResponse object

    :ivar error:
        None, or a unicode string explaining why the assessment could not be
        trusted (e.g. the responder signature/authorization callback failed)
    """

    status = None
    trusted = False
    revocation_time = None
    revocation_reason = None
    this_update = None
    next_update = None
    produced_at = None
    single_response = None
    error = None

    def __init__(self, status, trusted=False, revocation_time=None,
                 revocation_reason=None, this_update=None, next_update=None,
                 produced_at=None, single_response=None, error=None):
        self.status = status
        self.trusted = trusted
        self.revocation_time = revocation_time
        self.revocation_reason = revocation_reason
        self.this_update = this_update
        self.next_update = next_update
        self.produced_at = produced_at
        self.single_response = single_response
        self.error = error

    def __repr__(self):
        return '<OCSPResponseAssessment status=%s trusted=%r>' % (
            self.status,
            self.trusted
        )


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


def _coerce_aware(value):
    """
    Returns an aware UTC datetime for a possibly-naive datetime

    :param value:
        A datetime object
    :return:
        An aware datetime object
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    offset = value.utcoffset()
    if offset:
        value = value - offset
    return value.replace(tzinfo=timezone.utc)


def _cert_id_for_issuer(cert, issuer, hash_algo):
    """
    Computes the CertID hash components for a certificate/issuer pair

    :param cert:
        The target x509.Certificate object
    :param issuer:
        The issuing x509.Certificate object
    :param hash_algo:
        A unicode string naming the digest algorithm to use
    :return:
        A tuple of (issuer_name_hash bytes, issuer_key_hash bytes)
    """

    name_hash = hashlib.new(hash_algo, issuer.subject.dump()).digest()
    key_hash = hashlib.new(
        hash_algo,
        byte_cls(issuer.public_key['public_key'])
    ).digest()
    return name_hash, key_hash


def _cert_id_matches(cert_id, cert, issuer):
    """
    Determines if a CertID names the given certificate as issued by the given
    issuer, per RFC 6960 - comparing hash algorithm, issuerNameHash,
    issuerKeyHash and serial number

    :param cert_id:
        A CertId object
    :param cert:
        The target x509.Certificate object
    :param issuer:
        The issuing x509.Certificate object
    :return:
        A boolean
    """

    hash_algorithm = cert_id['hash_algorithm']
    hash_algo = hash_algorithm['algorithm'].native
    try:
        expected_name_hash, expected_key_hash = _cert_id_for_issuer(
            cert, issuer, hash_algo
        )
    except (ValueError, TypeError):
        return False

    # The hash algorithm must be usable for CertID matching - the algorithm
    # parameters must be the standard NULL/absent. An unrecognized OID maps to
    # a dotted-integer string rather than a known algorithm name.
    if hash_algorithm['parameters'].native is not None:
        return False

    return (
        cert_id['issuer_name_hash'].native == expected_name_hash
        and cert_id['issuer_key_hash'].native == expected_key_hash
        and cert_id['serial_number'].native == cert.serial_number
    )


def _request_has_cert_id(request, cert, issuer):
    """
    Determines if the request contains a request entry that names the
    certificate/issuer pair

    :param request:
        An OCSPRequest object, or None
    :param cert:
        The target x509.Certificate object
    :param issuer:
        The issuing x509.Certificate object
    :return:
        None when no request was supplied, otherwise a boolean
    """

    if request is None:
        return None
    for entry in request['tbs_request']['request_list']:
        if _cert_id_matches(entry['req_cert'], cert, issuer):
            return True
    return False


def _request_contains_cert_id(request, cert_id):
    """
    Determines if the request contains a request entry whose CertID is
    byte-for-byte identical to the one given

    :param request:
        An OCSPRequest object
    :param cert_id:
        A CertId object from a SingleResponse
    :return:
        A boolean
    """

    expected = cert_id.dump()
    for entry in request['tbs_request']['request_list']:
        if entry['req_cert'].dump() == expected:
            return True
    return False


def assess_ocsp_response(cert, issuer, response, evaluation_time, request=None,
                         responder_signature_callback=None,
                         max_age=None, skew=timedelta(minutes=5),
                         nonce_policy=NONCE_MATCH_IF_SENT):
    """
    Correlates an OCSP response with the target certificate, the issuing
    certificate and the original request, then evaluates the freshness of the
    answer against an explicit evaluation time. Parsing the
    BasicOCSPResponse successfully is not enough - this function verifies the
    response actually answers the request for the target certificate.

    The responder signature and authorization are never checked inside
    asn1crypto; the caller must supply a callback that confirms both. If the
    callback returns False or raises an exception, the assessment is returned
    with trusted=False, and a "good" status is downgraded so that no trusted
    positive answer can result.

    :param cert:
        The target x509.Certificate object whose status is being checked

    :param issuer:
        The issuing x509.Certificate object

    :param response:
        An OCSPResponse object

    :param evaluation_time:
        An aware or naive datetime at which the status is being evaluated;
        naive datetimes are assumed to be UTC

    :param request:
        The original OCSPRequest object, or None. When provided, the response
        must contain an answer for a CertID that was actually requested

    :param responder_signature_callback:
        A required callable invoked as
        responder_signature_callback(basic_ocsp_response, cert, issuer)
        that returns True when the signature is valid and the responder is
        authorized to answer for the issuer, and False (or raises) otherwise

    :param max_age:
        A timedelta limiting the age of a SingleResponse that omits
        nextUpdate, based on thisUpdate. None means nextUpdate is mandatory.
        Ignored when nextUpdate is present

    :param skew:
        A timedelta of allowed clock skew when comparing timestamps; defaults
        to five minutes

    :param nonce_policy:
        A unicode string of "match_if_sent" (the default; a response must echo
        a nonce the request included), "ignore" (never check the nonce), or
        "require" (a nonce must be sent and echoed)

    :raises:
        ValueError - when arguments are invalid
        OCSPResponseStatusError - when the response status is not successful
        OCSPResponseAssociationError - when the response does not answer the
            request for the target certificate, violates the nonce policy, or
            contains contradictory SingleResponses

    :return:
        An OCSPResponseAssessment object
    """

    if not isinstance(cert, Certificate):
        raise ValueError(unwrap(
            '''
            cert must be an instance of asn1crypto.x509.Certificate, not %s
            ''',
            type(cert).__name__
        ))
    if not isinstance(issuer, Certificate):
        raise ValueError(unwrap(
            '''
            issuer must be an instance of asn1crypto.x509.Certificate, not %s
            ''',
            type(issuer).__name__
        ))
    if not isinstance(response, OCSPResponse):
        raise ValueError(unwrap(
            '''
            response must be an instance of asn1crypto.ocsp.OCSPResponse, not
            %s
            ''',
            type(response).__name__
        ))
    if request is not None and not isinstance(request, OCSPRequest):
        raise ValueError(unwrap(
            '''
            request must be an instance of asn1crypto.ocsp.OCSPRequest or None,
            not %s
            ''',
            type(request).__name__
        ))
    if not isinstance(evaluation_time, datetime):
        raise ValueError(unwrap(
            '''
            evaluation_time must be an instance of datetime.datetime, not %s
            ''',
            type(evaluation_time).__name__
        ))
    if max_age is not None and not isinstance(max_age, timedelta):
        raise ValueError(unwrap(
            '''
            max_age must be an instance of datetime.timedelta or None, not %s
            ''',
            type(max_age).__name__
        ))
    if not isinstance(skew, timedelta):
        raise ValueError(unwrap(
            '''
            skew must be an instance of datetime.timedelta, not %s
            ''',
            type(skew).__name__
        ))
    if nonce_policy not in _NONCE_POLICIES:
        raise ValueError(unwrap(
            '''
            nonce_policy must be one of "ignore", "match_if_sent", "require",
            not %s
            ''',
            repr(nonce_policy)
        ))
    if responder_signature_callback is None:
        raise ValueError(unwrap(
            '''
            responder_signature_callback is required so that responder
            signature validity and authorization can be explicitly confirmed
            '''
        ))
    if not callable(responder_signature_callback):
        raise ValueError(unwrap(
            '''
            responder_signature_callback must be a callable, not %s
            ''',
            type(responder_signature_callback).__name__
        ))

    evaluation_time = _coerce_aware(evaluation_time)

    response_status = response['response_status'].native
    if response_status != 'successful':
        raise OCSPResponseStatusError(unwrap(
            '''
            The OCSP response could not be used to determine the status of the
            certificate because the responder returned the status "%s"
            ''',
            response_status
        ))

    if response['response_bytes'].native is None:
        raise OCSPResponseStatusError(unwrap(
            '''
            The OCSP response was marked successful but contained no response
            bytes
            '''
        ))

    response_bytes = response['response_bytes']
    if response_bytes['response_type'].native != 'basic_ocsp_response':
        raise OCSPResponseStatusError(unwrap(
            '''
            The OCSP response used the unsupported response type "%s"
            ''',
            response_bytes['response_type'].native
        ))

    basic = response_bytes['response'].parsed
    response_data = basic['tbs_response_data']

    if request is not None and not _request_has_cert_id(request, cert, issuer):
        raise OCSPResponseAssociationError(unwrap(
            '''
            The OCSP request did not ask about the target certificate
            '''
        ))

    request_nonce = None
    if request is not None:
        request_nonce = request.nonce_value
    response_nonce = response.nonce_value

    if nonce_policy == NONCE_REQUIRE:
        if request_nonce is None:
            raise OCSPResponseAssociationError(unwrap(
                '''
                Nonce policy is "require", but the request did not include a
                nonce
                '''
            ))
        if response_nonce is None or response_nonce.native != request_nonce.native:
            raise OCSPResponseAssociationError(unwrap(
                '''
                Nonce policy is "require", but the response did not echo the
                request nonce
                '''
            ))
    elif nonce_policy == NONCE_MATCH_IF_SENT and request_nonce is not None:
        if response_nonce is None or response_nonce.native != request_nonce.native:
            raise OCSPResponseAssociationError(unwrap(
                '''
                The OCSP response did not echo the nonce included in the
                request
                '''
            ))

    produced_at = _coerce_aware(response_data['produced_at'].native)
    if produced_at - skew > evaluation_time:
        raise OCSPResponseStatusError(unwrap(
            '''
            The OCSP response was produced at %s, which is after the evaluation
            time of %s (beyond the allowed clock skew)
            ''',
            produced_at.isoformat(),
            evaluation_time.isoformat()
        ))

    matches = []
    for single_response in response_data['responses']:
        cert_id = single_response['cert_id']
        if not _cert_id_matches(cert_id, cert, issuer):
            continue
        if request is not None and not _request_contains_cert_id(request, cert_id):
            continue
        matches.append(single_response)

    if not matches:
        return OCSPResponseAssessment(
            STATUS_NO_MATCH,
            produced_at=produced_at
        )

    # Group matching SingleResponses by the DER-encoded cert status.
    # Repeats of the same status are permitted (RFC 6960 4.4.2); the one with
    # the most recent thisUpdate is used. Distinct statuses for the same
    # certificate are contradictory and may not be resolved by simply taking
    # the first entry.
    by_status = {}
    for single_response in matches:
        signature = single_response['cert_status'].dump()
        candidate_this_update = _coerce_aware(
            single_response['this_update'].native
        )
        if signature not in by_status:
            by_status[signature] = single_response
        else:
            existing_this_update = _coerce_aware(
                by_status[signature]['this_update'].native
            )
            if candidate_this_update > existing_this_update:
                by_status[signature] = single_response

    if len(by_status) > 1:
        raise OCSPResponseAssociationError(unwrap(
            '''
            The OCSP response contained %d contradictory SingleResponses for the
            target certificate
            ''',
            len(by_status)
        ))

    single_response = list(by_status.values())[0]

    this_update = _coerce_aware(single_response['this_update'].native)
    next_update_native = single_response['next_update'].native
    next_update = _coerce_aware(next_update_native) if next_update_native else None

    # thisUpdate must not be later than the evaluation time
    if this_update - skew > evaluation_time:
        raise OCSPResponseStatusError(unwrap(
            '''
            The OCSP response thisUpdate value %s is after the evaluation time
            of %s (beyond the allowed clock skew)
            ''',
            this_update.isoformat(),
            evaluation_time.isoformat()
        ))

    fresh = True
    if next_update is not None:
        if next_update + skew < evaluation_time:
            fresh = False
    elif max_age is not None:
        age_limit = this_update + max_age
        if age_limit + skew < evaluation_time:
            fresh = False
    else:
        raise OCSPResponseStatusError(unwrap(
            '''
            The OCSP response for the certificate omits nextUpdate and no
            max_age limit was supplied, so the freshness of the answer can not
            be determined
            '''
        ))

    if not fresh:
        return OCSPResponseAssessment(
            STATUS_EXPIRED,
            this_update=this_update,
            next_update=next_update,
            produced_at=produced_at,
            single_response=single_response
        )

    cert_status = single_response['cert_status']
    status_name = cert_status.name
    revocation_time = None
    revocation_reason = None
    if status_name == 'revoked':
        revocation_time = _coerce_aware(
            cert_status.chosen['revocation_time'].native
        )
        revocation_reason = cert_status.chosen['revocation_reason'].native

    trusted = False
    error = None
    try:
        authorized = responder_signature_callback(basic, cert, issuer)
    except Exception as e:
        authorized = False
        error = 'Responder signature/authorization callback raised %s: %s' % (
            type(e).__name__,
            e
        )
    if not authorized:
        if error is None:
            error = unwrap(
                '''
                The responder signature callback did not confirm the signature
                and responder authorization
                '''
            )
    else:
        trusted = True

    if not trusted and status_name == 'good':
        status_name = STATUS_UNKNOWN

    return OCSPResponseAssessment(
        status_name,
        trusted=trusted,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
        this_update=this_update,
        next_update=next_update,
        produced_at=produced_at,
        single_response=single_response,
        error=error
    )
