# coding: utf-8

"""
ASN.1 type classes for the time stamp protocol (TSP). Exports the following
items:

- TimeStampReq()
- TimeStampResp()
- TimeStampVerificationResult()
- verify_time_stamp_response()

Also adds TimeStampedData() support to asn1crypto.cms.ContentInfo(),
TimeStampedData() and TSTInfo() support to
asn1crypto.cms.EncapsulatedContentInfo() and some oids and value parsers to
asn1crypto.cms.CMSAttribute().

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._types import byte_cls, str_cls
from .algos import DigestAlgorithm
from .cms import (
    CMSAttribute,
    CMSAttributeType,
    ContentInfo,
    ContentType,
    EncapsulatedContentInfo,
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
    UTF8String,
)
from .crl import CertificateList
from .x509 import (
    Attributes,
    Certificate,
    CertificatePolicies,
    GeneralName,
    GeneralNames,
)

import hashlib
from datetime import timedelta


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

    def verify(self, request, signature_verifier, allowed_policies=None):
        return verify_time_stamp_response(
            self,
            request,
            signature_verifier,
            allowed_policies
        )


class TimeStampVerificationResult(object):
    """
    The semantic result of checking a TimeStampResp against a TimeStampReq
    """

    def __init__(self, valid, reason=None, status=None, fail_info=None,
                 status_string=None,
                 tst_info=None, signer_certificate=None, time_range=None,
                 ordering=False):
        self.valid = valid
        self.ok = valid
        self.reason = reason
        self.status = status
        self.fail_info = fail_info
        self.status_string = status_string
        self.tst_info = tst_info
        self.signer_certificate = signer_certificate
        self.time_range = time_range
        self.local_ordering = ordering
        if time_range is None:
            self.not_before = None
            self.not_after = None
        else:
            self.not_before, self.not_after = time_range
        self.ordering = ordering

    def __bool__(self):
        return self.valid

    def __nonzero__(self):
        return self.valid

    def __repr__(self):
        if self.valid:
            detail = 'valid'
        else:
            detail = 'invalid, reason=%r' % self.reason
        return '<asn1crypto.tsp.TimeStampVerificationResult %s>' % detail


def _rejection_result(response, reason):
    status_info = response['status']
    fail_info = status_info['fail_info']
    return TimeStampVerificationResult(
        False,
        reason=reason,
        status=status_info['status'].native,
        fail_info=fail_info.native if fail_info.native is not None else None,
        status_string=status_info['status_string'].native
    )


def _signed_attribute(signer_info, name):
    matches = []
    for attribute in signer_info['signed_attrs']:
        if attribute['type'].native == name:
            matches.append(attribute)
    if len(matches) != 1:
        return None
    return matches[0]


def _digest_name(algorithm):
    name = algorithm['algorithm'].native
    return {
        'md5': 'md5',
        'sha1': 'sha1',
        'sha224': 'sha224',
        'sha256': 'sha256',
        'sha384': 'sha384',
        'sha512': 'sha512',
        'sha512_224': 'sha512_224',
        'sha512_256': 'sha512_256',
        'sha3_224': 'sha3_224',
        'sha3_256': 'sha3_256',
        'sha3_384': 'sha3_384',
        'sha3_512': 'sha3_512',
    }.get(name)


def _valid_digest_algorithm(algorithm):
    return algorithm['parameters'].native is None


def _certificate_matches_sid(certificate, signer_info):
    sid = signer_info['sid']
    if sid.name == 'issuer_and_serial_number':
        return certificate['tbs_certificate']['issuer'] == sid.chosen['issuer'] and \
            certificate['tbs_certificate']['serial_number'].native == \
            sid.chosen['serial_number'].native

    key_identifier = certificate.key_identifier_value
    return key_identifier is not None and key_identifier.native == sid.chosen.native


def _find_certificate(signed_data, signer_info):
    certificates = signed_data['certificates']
    if certificates.native is None:
        return None

    for certificate_choice in certificates:
        if certificate_choice.name != 'certificate':
            continue
        certificate = certificate_choice.chosen
        if _certificate_matches_sid(certificate, signer_info):
            return certificate
    return None


def _certificate_is_tsa(certificate):
    eku = certificate.extended_key_usage_value
    if eku is None:
        return False

    purposes = set(eku.native)
    if 'any_extended_key_usage' in purposes:
        return False
    if purposes != set(['time_stamping']):
        return False

    if 'extended_key_usage' not in certificate.critical_extensions:
        return False

    key_usage = certificate.key_usage_value
    if key_usage is not None and 'digital_signature' not in key_usage.native:
        return False

    basic_constraints = certificate.basic_constraints_value
    if basic_constraints is not None and basic_constraints['ca'].native:
        return False

    return True


def _tsa_matches_certificate(tsa_name, certificate):
    if tsa_name.name in ('other_name', 'x400_address', 'edi_party_name'):
        return False

    if tsa_name.name == 'directory_name':
        return tsa_name.chosen == certificate['tbs_certificate']['subject']

    alt_name = certificate.subject_alt_name_value
    if alt_name is None:
        return False

    for general_name in alt_name:
        try:
            if general_name == tsa_name:
                return True
        except ValueError:
            continue
    return False


def _cert_identifier_matches(identifier, certificate, default_algorithm=None):
    if 'hash_algorithm' in identifier:
        hash_algorithm = identifier['hash_algorithm']
    else:
        hash_algorithm = DigestAlgorithm(
            {'algorithm': default_algorithm or 'sha256'}
        )

    digest_name = _digest_name(hash_algorithm)
    if digest_name is None or not hasattr(hashlib, digest_name):
        return False

    digest = getattr(hashlib, digest_name)(certificate.dump()).digest()
    if digest != identifier['cert_hash'].native:
        return False

    issuer_serial = identifier['issuer_serial']
    if issuer_serial.native is None:
        return True

    if 'serial_number' in issuer_serial:
        serial_field = issuer_serial['serial_number']
    else:
        serial_field = issuer_serial['serial']
    if certificate['tbs_certificate']['serial_number'].native != \
            serial_field.native:
        return False

    for issuer_name in issuer_serial['issuer']:
        if issuer_name.name == 'directory_name' and \
                issuer_name.chosen == certificate['tbs_certificate']['issuer']:
            return True
    return False


def _check_signing_certificate(signed_attrs, certificate):
    v1 = _signed_attribute_from_set(signed_attrs, 'signing_certificate')
    v2 = _signed_attribute_from_set(signed_attrs, 'signing_certificate_v2')
    attributes = [attribute for attribute in (v1, v2) if attribute is not None]
    if len(attributes) != 1:
        return False

    attribute = attributes[0]
    if len(attribute['values']) != 1 or len(attribute['values'][0]['certs']) < 1:
        return False

    default_algorithm = 'sha1' if attribute['type'].native == \
        'signing_certificate' else 'sha256'
    return _cert_identifier_matches(
        attribute['values'][0]['certs'][0],
        certificate,
        default_algorithm
    )


def _signed_attribute_from_set(signed_attrs, name):
    matches = [attribute for attribute in signed_attrs
               if attribute['type'].native == name]
    return matches[0] if len(matches) == 1 else None


def _accuracy_range(tst_info):
    accuracy = tst_info['accuracy']
    if accuracy.native is None:
        lower_delta = timedelta()
        upper_delta = timedelta()
    else:
        seconds = accuracy['seconds'].native or 0
        millis = accuracy['millis'].native
        micros = accuracy['micros'].native
        millis = 0 if millis is None else millis
        micros = 0 if micros is None else micros
        if seconds < 0 or millis < 0 or micros < 0 or \
                seconds > 999 or millis > 999 or micros > 999 or \
                (accuracy['millis'].native is not None and millis < 1) or \
                (accuracy['micros'].native is not None and micros < 1):
            return None
        microseconds = seconds * 1000000 + millis * 1000 + micros
        lower_delta = timedelta(microseconds=microseconds)
        upper_delta = timedelta(microseconds=microseconds)

    gen_time = tst_info['gen_time'].native
    return gen_time - lower_delta, gen_time + upper_delta


def verify_time_stamp_response(response, request, signature_verifier,
                               allowed_policies=None):
    """
    Verifies that a TimeStampResp corresponds to a TimeStampReq

    Cryptographic signature and certificate chain validation are delegated to
    signature_verifier. That callable is invoked with the SignedData,
    SignerInfo, TSTInfo and encoded SET-tagged signed attributes. It must
    return the chain-validated TSA x509.Certificate, or True when the TSA
    certificate is embedded and selected by the SignerInfo's SID.

    :param response:
        A tsp.TimeStampResp

    :param request:
        A tsp.TimeStampReq

    :param signature_verifier:
        A callable used to verify the CMS signature and certificate chain

    :param allowed_policies:
        An iterable of acceptable TST policy OID unicode strings, or None to
        accept any policy

    :return:
        A tsp.TimeStampVerificationResult

    The ordering value is only the TSTInfo's local ordering flag for tokens
    issued under the same TSA key; it must not be interpreted as a global
    ordering between different TSAs.
    """

    if isinstance(response, byte_cls):
        response = TimeStampResp.load(response)
    if isinstance(request, byte_cls):
        request = TimeStampReq.load(request)

    status_info = response['status']
    status = status_info['status'].native
    if status not in ('granted', 'granted_with_mods'):
        return _rejection_result(response, 'pki_status')

    if status_info['fail_info'].native is not None:
        return _rejection_result(response, 'pki_status')

    token = response['time_stamp_token']
    if token.native is None:
        return _rejection_result(response, 'missing_time_stamp_token')

    if token['content_type'].native != 'signed_data':
        return _rejection_result(response, 'invalid_token_content_type')

    signed_data = token['content']
    encap_content_info = signed_data['encap_content_info']
    is_legacy_content_info = isinstance(encap_content_info, ContentInfo)
    if isinstance(encap_content_info, ContentInfo):
        legacy_tst_info = encap_content_info['content']
        if encap_content_info['content_type'].native != 'tst_info' or \
                not isinstance(legacy_tst_info, TSTInfo):
            return _rejection_result(response, 'invalid_tst_info_content_type')
    elif encap_content_info['content_type'].native != 'tst_info':
        return _rejection_result(response, 'invalid_tst_info_content_type')

    if not is_legacy_content_info and \
            encap_content_info['content'].native is None:
        return _rejection_result(response, 'missing_tst_info')

    if is_legacy_content_info:
        tst_info = legacy_tst_info
        tst_info_bytes = tst_info.dump()
    else:
        tst_info = encap_content_info['content'].parsed
        tst_info_bytes = encap_content_info['content'].contents
    if not isinstance(tst_info, TSTInfo) or tst_info['version'].native != 'v1':
        return _rejection_result(response, 'invalid_tst_info')

    signer_infos = signed_data['signer_infos']
    if len(signer_infos) != 1:
        return _rejection_result(response, 'invalid_signer_infos')

    signer_info = signer_infos[0]
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs.native is None:
        return _rejection_result(response, 'missing_signed_attributes')

    content_type_attribute = _signed_attribute(signer_info, 'content_type')
    if content_type_attribute is None or \
            len(content_type_attribute['values']) != 1 or \
            content_type_attribute['values'][0].native != 'tst_info':
        return _rejection_result(response, 'invalid_content_type_attribute')

    message_digest_attribute = _signed_attribute(signer_info, 'message_digest')
    if message_digest_attribute is None or \
            len(message_digest_attribute['values']) != 1:
        return _rejection_result(response, 'invalid_message_digest_attribute')

    digest_name = _digest_name(signer_info['digest_algorithm'])
    if digest_name is None or not hasattr(hashlib, digest_name) or \
            not _valid_digest_algorithm(signer_info['digest_algorithm']):
        return _rejection_result(response, 'unsupported_digest_algorithm')

    content_digest = getattr(hashlib, digest_name)(
        tst_info_bytes
    ).digest()
    if message_digest_attribute['values'][0].native != content_digest:
        return _rejection_result(response, 'message_digest_mismatch')

    signed_attrs_bytes = bytearray(signed_attrs.dump())
    signed_attrs_bytes[0] = 0x31
    signed_attrs_bytes = bytes(signed_attrs_bytes)

    try:
        verifier_result = signature_verifier(
            signed_data,
            signer_info,
            tst_info,
            signed_attrs_bytes
        )
        if verifier_result is False:
            return _rejection_result(response, 'signature_failed')

        if verifier_result is True:
            certificate = None
        elif isinstance(verifier_result, (tuple, list)):
            if verifier_result and isinstance(verifier_result[0], Certificate):
                certificate = verifier_result[0]
            else:
                return _rejection_result(response, 'signature_failed')
        elif isinstance(verifier_result, Certificate):
            certificate = verifier_result
        else:
            return _rejection_result(response, 'signature_failed')
    except Exception:
        return _rejection_result(response, 'signature_failed')

    if certificate is None:
        certificate = _find_certificate(signed_data, signer_info)
    if certificate is None:
        return _rejection_result(response, 'missing_tsa_certificate')

    if not _certificate_matches_sid(certificate, signer_info):
        return _rejection_result(response, 'signer_certificate_mismatch')

    if not _check_signing_certificate(signed_attrs, certificate):
        return _rejection_result(response, 'signing_certificate_attribute_invalid')

    if not _certificate_is_tsa(certificate):
        return _rejection_result(response, 'invalid_tsa_certificate_purpose')

    tsa_name = tst_info['tsa']
    if tsa_name.native is not None and \
            not _tsa_matches_certificate(tsa_name, certificate):
        return _rejection_result(response, 'tsa_identity_mismatch')

    request_policy = request['req_policy']
    if request_policy.native is not None and \
            tst_info['policy'].native != request_policy.native:
        return _rejection_result(response, 'unaccepted_policy')

    if allowed_policies is not None:
        if isinstance(allowed_policies, str_cls):
            allowed_policies = set([allowed_policies])
        else:
            allowed_policies = set(allowed_policies)
        if tst_info['policy'].native not in allowed_policies:
            return _rejection_result(response, 'unaccepted_policy')

    request_imprint = request['message_imprint']
    response_imprint = tst_info['message_imprint']
    if request_imprint['hash_algorithm']['algorithm'].native != \
            response_imprint['hash_algorithm']['algorithm'].native or \
            not _valid_digest_algorithm(request_imprint['hash_algorithm']) or \
            not _valid_digest_algorithm(response_imprint['hash_algorithm']) or \
            request_imprint['hashed_message'].native != \
            response_imprint['hashed_message'].native:
        return _rejection_result(response, 'message_imprint_mismatch')

    try:
        expected_length = len(getattr(
            hashlib,
            _digest_name(response_imprint['hash_algorithm'])
        )(b'').digest())
    except TypeError:
        return _rejection_result(response, 'unsupported_digest_algorithm')
    if len(response_imprint['hashed_message'].native) != expected_length:
        return _rejection_result(response, 'invalid_message_imprint')

    if request['nonce'].native != tst_info['nonce'].native:
        return _rejection_result(response, 'nonce_mismatch')

    time_range = _accuracy_range(tst_info)
    if time_range is None:
        return _rejection_result(response, 'invalid_accuracy')

    return TimeStampVerificationResult(
        True,
        reason=None,
        status=status,
        status_string=status_info['status_string'].native,
        tst_info=tst_info,
        signer_certificate=certificate,
        time_range=time_range,
        ordering=tst_info['ordering'].native
    )


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
ContentInfo._oid_specs['tst_info'] = TSTInfo
ContentInfo._oid_specs['timestamped_data'] = TimeStampedData
ContentType._map['1.2.840.113549.1.9.16.1.4'] = 'tst_info'
ContentType._map['1.2.840.113549.1.9.16.1.31'] = 'timestamped_data'
CMSAttributeType._map['1.2.840.113549.1.9.16.2.12'] = 'signing_certificate'
CMSAttribute._oid_specs['signing_certificate'] = SetOfSigningCertificates
CMSAttributeType._map['1.2.840.113549.1.9.16.2.47'] = 'signing_certificate_v2'
CMSAttribute._oid_specs['signing_certificate_v2'] = SetOfSigningCertificatesV2
