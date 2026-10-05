# coding: utf-8

"""
ASN.1 type classes for the time stamp protocol (TSP). Exports the following
items:

 - TimeStampReq()
 - TimeStampResp()
 - VerifiedTimeStamp()
 - TSPVerificationError()
 - verify_tsp_response()

Also adds TimeStampedData() support to asn1crypto.cms.ContentInfo(),
TimeStampedData() and TSTInfo() support to
asn1crypto.cms.EncapsulatedContentInfo() and some oids and value parsers to
asn1crypto.cms.CMSAttribute().

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import datetime
import hashlib

from ._errors import unwrap
from .algos import DigestAlgorithm
from .cms import (
    CMSAttribute,
    CMSAttributeType,
    ContentInfo,
    ContentType,
    EncapsulatedContentInfo,
    SignedData,
    SignerInfo,
)
from .core import (
    Any,
    BitString,
    Boolean,
    Choice,
    GeneralizedTime,
    IA5String,
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
    SetOf,
    VOID,
    UTF8String,
)
from .crl import CertificateList
from .x509 import (
    Attributes,
    CertificatePolicies,
    GeneralName,
    GeneralNames,
)


# The structures in this file are based on https://tools.ietf.org/html/rfc3161,
# https://tools.ietf.org/html/rfc4998, https://tools.ietf.org/html/rfc5544,
# https://tools.ietf.org/html/rfc5035, https://tools.ietf.org/html/rfc2634

class Version(Integer):
    _map = {
        0: 'v0',
        1: 'v1',
        2: 'v2',
        3: 'v3',
        4: 'v4',
        5: 'v5',
    }


class MessageImprint(Sequence):
    _fields = [
        ('hash_algorithm', DigestAlgorithm),
        ('hashed_message', OctetString),
    ]


class Accuracy(Sequence):
    _fields = [
        ('seconds', Integer, {'optional': True}),
        ('millis', Integer, {'implicit': 0, 'optional': True}),
        ('micros', Integer, {'implicit': 1, 'optional': True}),
    ]


class Extension(Sequence):
    _fields = [
        ('extn_id', ObjectIdentifier),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]


class Extensions(SequenceOf):
    _child_spec = Extension


class TSTInfo(Sequence):
    _fields = [
        ('version', Version),
        ('policy', ObjectIdentifier),
        ('message_imprint', MessageImprint),
        ('serial_number', Integer),
        ('gen_time', GeneralizedTime),
        ('accuracy', Accuracy, {'optional': True}),
        ('ordering', Boolean, {'default': False}),
        ('nonce', Integer, {'optional': True}),
        ('tsa', GeneralName, {'explicit': 0, 'optional': True}),
        ('extensions', Extensions, {'implicit': 1, 'optional': True}),
    ]


class TimeStampReq(Sequence):
    _fields = [
        ('version', Version),
        ('message_imprint', MessageImprint),
        ('req_policy', ObjectIdentifier, {'optional': True}),
        ('nonce', Integer, {'optional': True}),
        ('cert_req', Boolean, {'default': False}),
        ('extensions', Extensions, {'implicit': 0, 'optional': True}),
    ]


class PKIStatus(Integer):
    _map = {
        0: 'granted',
        1: 'granted_with_mods',
        2: 'rejection',
        3: 'waiting',
        4: 'revocation_warning',
        5: 'revocation_notification',
    }


class PKIFreeText(SequenceOf):
    _child_spec = UTF8String


class PKIFailureInfo(BitString):
    _map = {
        0: 'bad_alg',
        2: 'bad_request',
        5: 'bad_data_format',
        14: 'time_not_available',
        15: 'unaccepted_policy',
        16: 'unaccepted_extensions',
        17: 'add_info_not_available',
        25: 'system_failure',
    }


class PKIStatusInfo(Sequence):
    _fields = [
        ('status', PKIStatus),
        ('status_string', PKIFreeText, {'optional': True}),
        ('fail_info', PKIFailureInfo, {'optional': True}),
    ]


class TimeStampResp(Sequence):
    _fields = [
        ('status', PKIStatusInfo),
        ('time_stamp_token', ContentInfo, {'optional': True}),
    ]


class MetaData(Sequence):
    _fields = [
        ('hash_protected', Boolean),
        ('file_name', UTF8String, {'optional': True}),
        ('media_type', IA5String, {'optional': True}),
        ('other_meta_data', Attributes, {'optional': True}),
    ]


class TimeStampAndCRL(Sequence):
    _fields = [
        ('time_stamp', EncapsulatedContentInfo),
        ('crl', CertificateList, {'optional': True}),
    ]


class TimeStampTokenEvidence(SequenceOf):
    _child_spec = TimeStampAndCRL


class DigestAlgorithms(SequenceOf):
    _child_spec = DigestAlgorithm


class EncryptionInfo(Sequence):
    _fields = [
        ('encryption_info_type', ObjectIdentifier),
        ('encryption_info_value', Any),
    ]


class PartialHashtree(SequenceOf):
    _child_spec = OctetString


class PartialHashtrees(SequenceOf):
    _child_spec = PartialHashtree


class ArchiveTimeStamp(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm, {'implicit': 0, 'optional': True}),
        ('attributes', Attributes, {'implicit': 1, 'optional': True}),
        ('reduced_hashtree', PartialHashtrees, {'implicit': 2, 'optional': True}),
        ('time_stamp', ContentInfo),
    ]


class ArchiveTimeStampSequence(SequenceOf):
    _child_spec = ArchiveTimeStamp


class EvidenceRecord(Sequence):
    _fields = [
        ('version', Version),
        ('digest_algorithms', DigestAlgorithms),
        ('crypto_infos', Attributes, {'implicit': 0, 'optional': True}),
        ('encryption_info', EncryptionInfo, {'implicit': 1, 'optional': True}),
        ('archive_time_stamp_sequence', ArchiveTimeStampSequence),
    ]


class OtherEvidence(Sequence):
    _fields = [
        ('oe_type', ObjectIdentifier),
        ('oe_value', Any),
    ]


class Evidence(Choice):
    _alternatives = [
        ('tst_evidence', TimeStampTokenEvidence, {'implicit': 0}),
        ('ers_evidence', EvidenceRecord, {'implicit': 1}),
        ('other_evidence', OtherEvidence, {'implicit': 2}),
    ]


class TimeStampedData(Sequence):
    _fields = [
        ('version', Version),
        ('data_uri', IA5String, {'optional': True}),
        ('meta_data', MetaData, {'optional': True}),
        ('content', OctetString, {'optional': True}),
        ('temporal_evidence', Evidence),
    ]


class IssuerSerial(Sequence):
    _fields = [
        ('issuer', GeneralNames),
        ('serial_number', Integer),
    ]


class ESSCertID(Sequence):
    _fields = [
        ('cert_hash', OctetString),
        ('issuer_serial', IssuerSerial, {'optional': True}),
    ]


class ESSCertIDs(SequenceOf):
    _child_spec = ESSCertID


class SigningCertificate(Sequence):
    _fields = [
        ('certs', ESSCertIDs),
        ('policies', CertificatePolicies, {'optional': True}),
    ]


class SetOfSigningCertificates(SetOf):
    _child_spec = SigningCertificate


class ESSCertIDv2(Sequence):
    _fields = [
        ('hash_algorithm', DigestAlgorithm, {'default': {'algorithm': 'sha256'}}),
        ('cert_hash', OctetString),
        ('issuer_serial', IssuerSerial, {'optional': True}),
    ]


class ESSCertIDv2s(SequenceOf):
    _child_spec = ESSCertIDv2


class SigningCertificateV2(Sequence):
    _fields = [
        ('certs', ESSCertIDv2s),
        ('policies', CertificatePolicies, {'optional': True}),
    ]


class SetOfSigningCertificatesV2(SetOf):
    _child_spec = SigningCertificateV2


EncapsulatedContentInfo._oid_specs['tst_info'] = TSTInfo
EncapsulatedContentInfo._oid_specs['timestamped_data'] = TimeStampedData
ContentInfo._oid_specs['timestamped_data'] = TimeStampedData
ContentType._map['1.2.840.113549.1.9.16.1.4'] = 'tst_info'
ContentType._map['1.2.840.113549.1.9.16.1.31'] = 'timestamped_data'
CMSAttributeType._map['1.2.840.113549.1.9.16.2.12'] = 'signing_certificate'
CMSAttribute._oid_specs['signing_certificate'] = SetOfSigningCertificates
CMSAttributeType._map['1.2.840.113549.1.9.16.2.47'] = 'signing_certificate_v2'
CMSAttribute._oid_specs['signing_certificate_v2'] = SetOfSigningCertificatesV2


# RFC 3161 requires the digest algorithm OID to name the digest applied to
# the message. Locally recomputing CMS/ESS digests is only possible for
# algorithms available through hashlib with a fixed-length digest.
_HASHLIB_NAMES = {
    'md5': 'md5',
    'sha1': 'sha1',
    'sha224': 'sha224',
    'sha256': 'sha256',
    'sha384': 'sha384',
    'sha512': 'sha512',
    'sha3_224': 'sha3_224',
    'sha3_256': 'sha3_256',
    'sha3_384': 'sha3_384',
    'sha3_512': 'sha3_512',
}


class TSPVerificationError(Exception):
    """
    An exception indicating a TimeStampResp does not correspond to the
    TimeStampReq it was issued for, or is malformed. The first element of
    :attr:`args` is a unicode string containing one of the reason constants
    defined on this class.
    """

    # PKIStatus was not "granted" (0) or "granted_with_mods" (1)
    bad_status = 'bad_status'

    # The response/request bytes or token structure could not be parsed
    malformed = 'malformed'

    # A granted response carried no TimeStampToken
    no_token = 'no_token'

    # The TimeStampToken was not a CMS SignedData structure
    invalid_token = 'invalid_token'

    # The SignedData did not contain exactly one SignerInfo
    invalid_signer_infos = 'invalid_signer_infos'

    # The encapsulated content was not a TSTInfo
    invalid_content = 'invalid_content'

    # The TSTInfo version was not v1
    invalid_tst_version = 'invalid_tst_version'

    # The accuracy field contained negative or out-of-range components
    invalid_accuracy = 'invalid_accuracy'

    # The messageImprint algorithm OID did not match the request
    invalid_message_imprint_algorithm = 'invalid_message_imprint_algorithm'

    # The messageImprint digest did not match the request
    invalid_message_imprint_digest = 'invalid_message_imprint_digest'

    # The TSTInfo nonce did not echo the request nonce
    nonce_mismatch = 'nonce_mismatch'

    # The TSTInfo policy was not one of the acceptable policies
    invalid_policy = 'invalid_policy'

    # A SignedAttribute (content type, message digest, ESS cert id) was
    # missing or incorrect
    invalid_signed_attributes = 'invalid_signed_attributes'

    # The signing certificate could not be located or identified
    signer_certificate_missing = 'signer_certificate_missing'

    # The signing certificate is not authorised for time stamping
    invalid_tsa_certificate_purpose = 'invalid_tsa_certificate_purpose'

    # The TSTInfo.tsa name did not identify the signing certificate
    invalid_tsa_name = 'invalid_tsa_name'

    # The ESS signing-certificate identifier did not match the signer
    invalid_ess_cert_id = 'invalid_ess_cert_id'

    # The caller-supplied signature/certificate-chain callback failed
    signature_invalid = 'signature_invalid'

    def __init__(self, reason, status_info=None):
        """
        :param reason:
            One of the class-level reason constants

        :param status_info:
            Optional PKIStatusInfo object, retained for bad-status errors so
            the caller can inspect status, status_string and fail_info
        """

        super(TSPVerificationError, self).__init__(reason)
        self.reason = reason
        self.pki_status = None
        self.pki_status_string = None
        self.pki_failure_info = None
        if status_info is not None:
            status_field = status_info['status']
            self.pki_status = status_field.native
            status_string = status_info['status_string']
            if status_string is not VOID:
                self.pki_status_string = status_string.native
            fail_info = status_info['fail_info']
            if fail_info is not VOID:
                self.pki_failure_info = fail_info.native


class VerifiedTimeStamp(object):
    """
    The result of :func:`verify_tsp_response`.

    ``gen_time_lower`` and ``gen_time_upper`` are the explicit time interval
    formed from gen_time and accuracy (gen_time +/- (seconds + millis/1000 +
    micros/1000000)); without accuracy both equal ``gen_time``.

    ``ordering`` only reflects an ordering asserted by the issuing TSA among
    time stamps that it produced - it never implies a global ordering between
    tokens issued by different TSAs.
    """

    def __init__(self, response, tst_info, signer_certificate):
        self._response = response
        self._tst_info = tst_info
        self._signer_certificate = signer_certificate

        gen_time = tst_info['gen_time'].native
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=datetime.timezone.utc)
        self._gen_time = gen_time

        seconds = 0
        millis = 0
        micros = 0
        accuracy = tst_info['accuracy']
        if accuracy is not VOID:
            if accuracy['seconds'] is not VOID:
                seconds = int(accuracy['seconds'].native)
            if accuracy['millis'] is not VOID:
                millis = int(accuracy['millis'].native)
            if accuracy['micros'] is not VOID:
                micros = int(accuracy['micros'].native)
        if seconds < 0 or not 0 <= millis <= 999 or not 0 <= micros <= 999:
            raise TSPVerificationError(TSPVerificationError.invalid_accuracy)
        accuracy_seconds = seconds + millis / 1000 + micros / 1000000
        self._accuracy_seconds = accuracy_seconds
        delta = datetime.timedelta(seconds=accuracy_seconds)
        self._gen_time_lower = gen_time - delta
        self._gen_time_upper = gen_time + delta

        self._ordering = bool(tst_info['ordering'].native)

    @property
    def response(self):
        """
        :return:
            The parsed TimeStampResp
        """

        return self._response

    @property
    def tst_info(self):
        """
        :return:
            The parsed TSTInfo
        """

        return self._tst_info

    @property
    def signer_certificate(self):
        """
        :return:
            The x509.Certificate identified as the signer
        """

        return self._signer_certificate

    @property
    def gen_time(self):
        """
        :return:
            A timezone-aware datetime of the claimed time of the token
        """

        return self._gen_time

    @property
    def accuracy_seconds(self):
        """
        :return:
            A float of the total accuracy, in seconds
        """

        return self._accuracy_seconds

    @property
    def gen_time_lower(self):
        """
        :return:
            A timezone-aware datetime of the start of the accuracy interval
        """

        return self._gen_time_lower

    @property
    def gen_time_upper(self):
        """
        :return:
            A timezone-aware datetime of the end of the accuracy interval
        """

        return self._gen_time_upper

    @property
    def ordering(self):
        """
        :return:
            A boolean; True orders tokens from this TSA only, never across
            different TSAs
        """

        return self._ordering

    @property
    def policy(self):
        """
        :return:
            A unicode string of the dotted TSTInfo policy OID
        """

        return self._tst_info['policy'].dotted

    @property
    def message_imprint(self):
        """
        :return:
            The MessageImprint from the TSTInfo
        """

        return self._tst_info['message_imprint']

    @property
    def serial_number(self):
        """
        :return:
            An int of the TSA-assigned time-stamp serial number
        """

        return self._tst_info['serial_number'].native


def _digest(algorithm_name, data):
    """
    Computes a message digest using hashlib

    :param algorithm_name:
        A native DigestAlgorithm name (e.g. 'sha256')

    :param data:
        A byte string

    :return:
        A byte string of the digest
    """

    hashlib_name = _HASHLIB_NAMES[algorithm_name]
    return hashlib.new(hashlib_name, data).digest()


def _signed_attrs(signer_info):
    """
    :param signer_info:
        A SignerInfo object

    :return:
        A dict of attribute type name to CMSAttribute, plus a count of
        attributes ("__count__") so duplicate attributes are detectable
    """

    result = {'__count__': 0}
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs is VOID:
        return result
    for attribute in signed_attrs:
        result['__count__'] += 1
        result[attribute['type'].native] = attribute
    return result


def _find_signer_certificate(signed_data, signer_info, signer_certificate):
    """
    Locates the certificate corresponding to the SignerInfo sid, using
    certificates embedded in the SignedData and an optional caller-supplied
    certificate.

    :param signed_data:
        A SignedData object

    :param signer_info:
        The SignerInfo object

    :param signer_certificate:
        None, or an x509.Certificate / byte string of the signer DER

    :return:
        An x509.Certificate, or None if no matching certificate is available
    """

    from .x509 import Certificate as X509Certificate

    if signer_certificate is not None and not isinstance(
        signer_certificate, X509Certificate
    ):
        signer_certificate = X509Certificate.load(signer_certificate)

    candidates = []
    certificates = signed_data['certificates']
    if certificates is not VOID:
        for choice in certificates:
            if choice.name == 'certificate':
                candidates.append(choice.chosen)
    if signer_certificate is not None:
        candidates.append(signer_certificate)

    sid = signer_info['sid']
    if sid.name == 'issuer_and_serial_number':
        issuer = sid.chosen['issuer']
        serial_number = sid.chosen['serial_number'].native
        for candidate in candidates:
            if candidate.issuer == issuer and candidate.serial_number == serial_number:
                return candidate
        return None

    key_identifier = sid.chosen.native
    for candidate in candidates:
        ski = candidate.key_identifier_value
        if ski is not None and ski.native == key_identifier:
            return candidate
    return None


def _check_ess_cert_id(attrs, signer_certificate):
    """
    Verifies the ESS signing-certificate attribute required by RFC 3161
    (signing-certificate for SHA-1, signing-certificate-v2 otherwise) binds
    the SignedData to the signer certificate.

    :param attrs:
        The dict returned by _signed_attrs()

    :param signer_certificate:
        An x509.Certificate

    :raises:
        TSPVerificationError - when the attribute is absent, duplicated or
        does not match the signer certificate
    """

    has_v1 = 'signing_certificate' in attrs
    has_v2 = 'signing_certificate_v2' in attrs
    if not has_v1 and not has_v2:
        raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)

    def match(attribute, default_algorithm, v2):
        if len(attribute['values']) != 1:
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)
        signing_certificate = attribute['values'][0]
        cert_ids = signing_certificate['certs']
        if len(cert_ids) < 1:
            raise TSPVerificationError(TSPVerificationError.invalid_ess_cert_id)
        cert_id = cert_ids[0]
        if v2:
            algorithm = cert_id['hash_algorithm']['algorithm'].native
        else:
            algorithm = default_algorithm
        cert_hash = cert_id['cert_hash'].native
        expected = _digest(algorithm, signer_certificate.dump())
        if cert_hash != expected:
            raise TSPVerificationError(TSPVerificationError.invalid_ess_cert_id)
        issuer_serial = cert_id['issuer_serial']
        if issuer_serial is not VOID:
            serial_number = issuer_serial['serial_number'].native
            if serial_number != signer_certificate.serial_number:
                raise TSPVerificationError(TSPVerificationError.invalid_ess_cert_id)

    if has_v1:
        match(attrs['signing_certificate'], 'sha1', False)
    if has_v2:
        match(attrs['signing_certificate_v2'], 'sha256', True)


def _check_signer_purpose(signer_certificate):
    """
    Confirms the signer certificate is authorised for time stamping per
    RFC 3161: the extended key usage extension must be present, critical
    (per RFC 3161 2.3.5), and assert keyPurposeId id-kp-timeStamping; key
    usage, when present, must assert digitalSignature.

    :param signer_certificate:
        An x509.Certificate

    :raises:
        TSPVerificationError - when the certificate purpose is invalid
    """

    eku = signer_certificate.extended_key_usage_value
    if eku is None:
        raise TSPVerificationError(TSPVerificationError.invalid_tsa_certificate_purpose)
    if 'extended_key_usage' not in signer_certificate.critical_extensions:
        raise TSPVerificationError(TSPVerificationError.invalid_tsa_certificate_purpose)
    key_purposes = set(eku.native)
    if 'time_stamping' not in key_purposes:
        raise TSPVerificationError(TSPVerificationError.invalid_tsa_certificate_purpose)

    key_usage = signer_certificate.key_usage_value
    if key_usage is not None and 'digital_signature' not in key_usage.native:
        raise TSPVerificationError(TSPVerificationError.invalid_tsa_certificate_purpose)


def _check_tsa_name(tst_info, signer_certificate):
    """
    Confirms an explicit TSTInfo.tsa general name identifies the signing
    certificate. Only directoryName is supported, and it must equal the
    signer certificate subject exactly.

    :param tst_info:
        A TSTInfo object

    :param signer_certificate:
        An x509.Certificate

    :raises:
        TSPVerificationError - when the TSA name is wrong
    """

    tsa = tst_info['tsa']
    if tsa is VOID:
        return
    if tsa.name != 'directory_name':
        raise TSPVerificationError(TSPVerificationError.invalid_tsa_name)
    if tsa.chosen != signer_certificate.subject:
        raise TSPVerificationError(TSPVerificationError.invalid_tsa_name)


def verify_tsp_response(response, request, signer_callback, signer_certificate=None,
                        acceptable_policies=None):
    """
    Verifies that a TimeStampResp corresponds to a specific TimeStampReq, per
    RFC 3161. Cryptographic signature validation and certificate chain
    validation are intentionally left to ``signer_callback`` - this function
    performs every protocol-level correspondence and purpose check that can be
    made without them, and only invokes the callback once those pass.

    It checks:

     - PKIStatus is granted (or granted_with_mods); a rejection, waiting,
       revocation or missing status raises bad_status carrying the TSA's
       status string and failure info
     - a granted response actually contains a TimeStampToken
     - the token is CMS SignedData with exactly one SignerInfo and a TSTInfo
       encapsulated content
     - the TSTInfo messageImprint algorithm OID and digest byte-for-byte match
       the request messageImprint
     - the TSTInfo nonce, when the request carried one, echoes it exactly
     - the TSTInfo policy is one of the acceptable policies (explicit
       parameter, or the request reqPolicy, or any policy when neither is
       given)
     - the SignedAttributes include a correct content type (tst_info), a
       message digest matching the eContent bytes, and an ESS
       signing-certificate identifier matching the signer certificate
     - the signer certificate (embedded in the SignedData or supplied) is a
       critical EKU certificate asserting id-kp-timeStamping, with
       digitalSignature key usage when a key usage extension is present
     - the TSTInfo.tsa name, when present, is a directoryName equal to the
       signer certificate subject

    The signature and certificate chain validation is then delegated to
    ``signer_callback``, which must raise an exception on failure.

    :param response:
        A TimeStampResp object, or a byte string of the DER-encoded response

    :param request:
        The TimeStampReq that was submitted - a TimeStampReq object or a byte
        string of DER

    :param signer_callback:
        A callable invoked as
        ``signer_callback(signer_certificate, signed_data, signer_info,
        tst_info, response)`` after all local checks pass. It is responsible
        for validating the signature on the SignedData and the certificate
        chain. Any exception it raises is re-raised as a
        TSPVerificationError with reason signature_invalid.

    :param signer_certificate:
        An optional x509.Certificate object or byte string of DER, used to
        identify the signer when the SignedData does not embed certificates.

    :param acceptable_policies:
        An optional iterable of policy OID strings (dotted or name) that are
        acceptable. Defaults to the request reqPolicy when present, or allows
        any policy.

    :raises:
        TSPVerificationError - when the response cannot be matched to the
        request

    :return:
        A VerifiedTimeStamp
    """

    if not isinstance(response, TimeStampResp):
        if isinstance(response, type(b'')):
            try:
                response = TimeStampResp.load(response)
            except (ValueError, TypeError):
                raise TSPVerificationError(TSPVerificationError.malformed)
        else:
            raise TypeError(unwrap(
                '''
                response must be a byte string or TimeStampResp object, not
                %s
                ''',
                type(response).__name__
            ))

    if not isinstance(request, TimeStampReq):
        if isinstance(request, type(b'')):
            try:
                request = TimeStampReq.load(request)
            except (ValueError, TypeError):
                raise TSPVerificationError(TSPVerificationError.malformed)
        else:
            raise TypeError(unwrap(
                '''
                request must be a byte string or TimeStampReq object, not
                %s
                ''',
                type(request).__name__
            ))

    try:
        status_info = response['status']
        status_name = status_info['status'].native
        if status_name not in ('granted', 'granted_with_mods'):
            raise TSPVerificationError(TSPVerificationError.bad_status, status_info)

        token = response['time_stamp_token']
        if token is VOID:
            # A granted status without a token is a malformed success - never a
            # verified empty result
            raise TSPVerificationError(TSPVerificationError.no_token, status_info)

        if token['content_type'].native != 'signed_data':
            raise TSPVerificationError(TSPVerificationError.invalid_token)
        signed_data = token['content']
        if not isinstance(signed_data, SignedData):
            raise TSPVerificationError(TSPVerificationError.invalid_token)

        signer_infos = signed_data['signer_infos']
        if len(signer_infos) != 1:
            raise TSPVerificationError(TSPVerificationError.invalid_signer_infos)
        signer_info = signer_infos[0]

        encap = signed_data['encap_content_info']
        if encap['content_type'].native != 'tst_info':
            raise TSPVerificationError(TSPVerificationError.invalid_content)
        if encap['content'] is VOID:
            raise TSPVerificationError(TSPVerificationError.invalid_content)
        tst_info = encap['content'].parsed
        if not isinstance(tst_info, TSTInfo):
            raise TSPVerificationError(TSPVerificationError.invalid_content)

        if tst_info['version'].native != 'v1':
            raise TSPVerificationError(TSPVerificationError.invalid_tst_version)

        request_imprint = request['message_imprint']
        response_imprint = tst_info['message_imprint']
        if (
            request_imprint['hash_algorithm']['algorithm'].dotted
            != response_imprint['hash_algorithm']['algorithm'].dotted
        ):
            raise TSPVerificationError(
                TSPVerificationError.invalid_message_imprint_algorithm
            )
        if request_imprint['hashed_message'].native != response_imprint['hashed_message'].native:
            raise TSPVerificationError(
                TSPVerificationError.invalid_message_imprint_digest
            )

        request_nonce = request['nonce']
        if request_nonce is not VOID:
            response_nonce = tst_info['nonce']
            if response_nonce is VOID or response_nonce.native != request_nonce.native:
                raise TSPVerificationError(TSPVerificationError.nonce_mismatch)

        if acceptable_policies is None:
            req_policy = request['req_policy']
            acceptable_policies = set() if req_policy is VOID else {req_policy.dotted}
        else:
            acceptable_policies = {
                ObjectIdentifier(policy).dotted if not hasattr(policy, 'dotted')
                else policy.dotted
                for policy in acceptable_policies
            }
        if acceptable_policies and tst_info['policy'].dotted not in acceptable_policies:
            raise TSPVerificationError(TSPVerificationError.invalid_policy)

        attrs = _signed_attrs(signer_info)
        if attrs['__count__'] < 3:
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)

        content_type_attr = attrs.get('content_type')
        if content_type_attr is None or len(content_type_attr['values']) != 1:
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)
        if content_type_attr['values'][0].native != 'tst_info':
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)

        message_digest_attr = attrs.get('message_digest')
        if message_digest_attr is None or len(message_digest_attr['values']) != 1:
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)
        econtent = tst_info.dump()
        digest_algorithm = signer_info['digest_algorithm']['algorithm'].native
        if digest_algorithm not in _HASHLIB_NAMES:
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)
        expected_digest = _digest(digest_algorithm, econtent)
        if message_digest_attr['values'][0].native != expected_digest:
            raise TSPVerificationError(TSPVerificationError.invalid_signed_attributes)

        signer_certificate = _find_signer_certificate(
            signed_data, signer_info, signer_certificate
        )
        if signer_certificate is None:
            raise TSPVerificationError(TSPVerificationError.signer_certificate_missing)

        _check_ess_cert_id(attrs, signer_certificate)
        _check_signer_purpose(signer_certificate)
        _check_tsa_name(tst_info, signer_certificate)

        try:
            signer_callback(
                signer_certificate,
                signed_data,
                signer_info,
                tst_info,
                response,
            )
        except TSPVerificationError:
            raise
        except Exception:
            raise TSPVerificationError(TSPVerificationError.signature_invalid)

    except TSPVerificationError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        raise TSPVerificationError(TSPVerificationError.malformed)

    return VerifiedTimeStamp(response, tst_info, signer_certificate)
