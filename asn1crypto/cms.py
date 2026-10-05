# coding: utf-8

"""
ASN.1 type classes for cryptographic message syntax (CMS). Structures are also
compatible with PKCS#7. Exports the following items:

 - AuthenticatedData()
 - AuthEnvelopedData()
 - CompressedData()
 - ContentInfo()
 - DigestedData()
 - EncryptedData()
 - EnvelopedData()
 - SignedAndEnvelopedData()
 - SignedData()
 - SignerVerificationMaterial()
 - extract_signer_verification_material()

Other type classes are defined that help compose the types listed above.

Most CMS structures in the wild are formatted as ContentInfo encapsulating one of the other types.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib

try:
    import zlib
except (ImportError):
    zlib = None

from ._types import byte_cls, chr_cls, str_cls
from .algos import (
    _ForceNullParameters,
    DigestAlgorithm,
    EncryptionAlgorithm,
    EncryptionAlgorithmId,
    HmacAlgorithm,
    KdfAlgorithm,
    RSAESOAEPParams,
    SignedDigestAlgorithm,
)
from .core import (
    Any,
    BitString,
    Choice,
    Enumerated,
    GeneralizedTime,
    Integer,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
    UTCTime,
    Void,
    UTF8String,
)
from .crl import CertificateList
from .keys import PublicKeyInfo
from .ocsp import OCSPResponse
from .x509 import Attributes, Certificate, Extensions, GeneralName, GeneralNames, Name


# These structures are taken from
# ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc

class ExtendedCertificateInfo(Sequence):
    _fields = [
        ('version', Integer),
        ('certificate', Certificate),
        ('attributes', Attributes),
    ]


class ExtendedCertificate(Sequence):
    _fields = [
        ('extended_certificate_info', ExtendedCertificateInfo),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


# These structures are taken from https://tools.ietf.org/html/rfc5652,
# https://tools.ietf.org/html/rfc5083, http://tools.ietf.org/html/rfc2315,
# https://tools.ietf.org/html/rfc5940, https://tools.ietf.org/html/rfc3274,
# https://tools.ietf.org/html/rfc3281


class CMSVersion(Integer):
    _map = {
        0: 'v0',
        1: 'v1',
        2: 'v2',
        3: 'v3',
        4: 'v4',
        5: 'v5',
    }


class CMSAttributeType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.3': 'content_type',
        '1.2.840.113549.1.9.4': 'message_digest',
        '1.2.840.113549.1.9.5': 'signing_time',
        '1.2.840.113549.1.9.6': 'counter_signature',
        # https://datatracker.ietf.org/doc/html/rfc2633#section-2.5.2
        '1.2.840.113549.1.9.15': 'smime_capabilities',
        # https://tools.ietf.org/html/rfc2633#page-26
        '1.2.840.113549.1.9.16.2.11': 'encrypt_key_pref',
        # https://tools.ietf.org/html/rfc3161#page-20
        '1.2.840.113549.1.9.16.2.14': 'signature_time_stamp_token',
        # https://tools.ietf.org/html/rfc6211#page-5
        '1.2.840.113549.1.9.52': 'cms_algorithm_protection',
        # https://docs.microsoft.com/en-us/previous-versions/hh968145(v%3Dvs.85)
        '1.3.6.1.4.1.311.2.4.1': 'microsoft_nested_signature',
        # Some places refer to this as SPC_RFC3161_OBJID, others szOID_RFC3161_counterSign.
        # https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
        # refers to szOID_RFC3161_counterSign as "1.2.840.113549.1.9.16.1.4",
        # but that OID is also called szOID_TIMESTAMP_TOKEN. Because of there being
        # no canonical source for this OID, we give it our own name
        '1.3.6.1.4.1.311.3.3.1': 'microsoft_time_stamp_token',
    }


class Time(Choice):
    _alternatives = [
        ('utc_time', UTCTime),
        ('generalized_time', GeneralizedTime),
    ]


class ContentType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.7.1': 'data',
        '1.2.840.113549.1.7.2': 'signed_data',
        '1.2.840.113549.1.7.3': 'enveloped_data',
        '1.2.840.113549.1.7.4': 'signed_and_enveloped_data',
        '1.2.840.113549.1.7.5': 'digested_data',
        '1.2.840.113549.1.7.6': 'encrypted_data',
        '1.2.840.113549.1.9.16.1.2': 'authenticated_data',
        '1.2.840.113549.1.9.16.1.9': 'compressed_data',
        '1.2.840.113549.1.9.16.1.23': 'authenticated_enveloped_data',
    }


class CMSAlgorithmProtection(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm),
        ('signature_algorithm', SignedDigestAlgorithm, {'implicit': 1, 'optional': True}),
        ('mac_algorithm', HmacAlgorithm, {'implicit': 2, 'optional': True}),
    ]


class SetOfContentType(SetOf):
    _child_spec = ContentType


class SetOfOctetString(SetOf):
    _child_spec = OctetString


class SetOfTime(SetOf):
    _child_spec = Time


class SetOfAny(SetOf):
    _child_spec = Any


class SetOfCMSAlgorithmProtection(SetOf):
    _child_spec = CMSAlgorithmProtection


class CMSAttribute(Sequence):
    _fields = [
        ('type', CMSAttributeType),
        ('values', None),
    ]

    _oid_specs = {}

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class CMSAttributes(SetOf):
    _child_spec = CMSAttribute


class IssuerSerial(Sequence):
    _fields = [
        ('issuer', GeneralNames),
        ('serial', Integer),
        ('issuer_uid', OctetBitString, {'optional': True}),
    ]


class AttCertVersion(Integer):
    _map = {
        0: 'v1',
        1: 'v2',
    }


class AttCertSubject(Choice):
    _alternatives = [
        ('base_certificate_id', IssuerSerial, {'explicit': 0}),
        ('subject_name', GeneralNames, {'explicit': 1}),
    ]


class AttCertValidityPeriod(Sequence):
    _fields = [
        ('not_before_time', GeneralizedTime),
        ('not_after_time', GeneralizedTime),
    ]


class AttributeCertificateInfoV1(Sequence):
    _fields = [
        ('version', AttCertVersion, {'default': 'v1'}),
        ('subject', AttCertSubject),
        ('issuer', GeneralNames),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', Attributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV1(Sequence):
    _fields = [
        ('ac_info', AttributeCertificateInfoV1),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class DigestedObjectType(Enumerated):
    _map = {
        0: 'public_key',
        1: 'public_key_cert',
        2: 'other_objy_types',
    }


class ObjectDigestInfo(Sequence):
    _fields = [
        ('digested_object_type', DigestedObjectType),
        ('other_object_type_id', ObjectIdentifier, {'optional': True}),
        ('digest_algorithm', DigestAlgorithm),
        ('object_digest', OctetBitString),
    ]


class Holder(Sequence):
    _fields = [
        ('base_certificate_id', IssuerSerial, {'implicit': 0, 'optional': True}),
        ('entity_name', GeneralNames, {'implicit': 1, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'implicit': 2, 'optional': True}),
    ]


class V2Form(Sequence):
    _fields = [
        ('issuer_name', GeneralNames, {'optional': True}),
        ('base_certificate_id', IssuerSerial, {'explicit': 0, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'explicit': 1, 'optional': True}),
    ]


class AttCertIssuer(Choice):
    _alternatives = [
        ('v1_form', GeneralNames),
        ('v2_form', V2Form, {'implicit': 0}),
    ]


class IetfAttrValue(Choice):
    _alternatives = [
        ('octets', OctetString),
        ('oid', ObjectIdentifier),
        ('string', UTF8String),
    ]


class IetfAttrValues(SequenceOf):
    _child_spec = IetfAttrValue


class IetfAttrSyntax(Sequence):
    _fields = [
        ('policy_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('values', IetfAttrValues),
    ]


class SetOfIetfAttrSyntax(SetOf):
    _child_spec = IetfAttrSyntax


class SvceAuthInfo(Sequence):
    _fields = [
        ('service', GeneralName),
        ('ident', GeneralName),
        ('auth_info', OctetString, {'optional': True}),
    ]


class SetOfSvceAuthInfo(SetOf):
    _child_spec = SvceAuthInfo


class RoleSyntax(Sequence):
    _fields = [
        ('role_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('role_name', GeneralName, {'explicit': 1}),
    ]


class SetOfRoleSyntax(SetOf):
    _child_spec = RoleSyntax


class ClassList(BitString):
    _map = {
        0: 'unmarked',
        1: 'unclassified',
        2: 'restricted',
        3: 'confidential',
        4: 'secret',
        5: 'top_secret',
    }


class SecurityCategory(Sequence):
    _fields = [
        ('type', ObjectIdentifier, {'implicit': 0}),
        ('value', Any, {'explicit': 1}),
    ]


class SetOfSecurityCategory(SetOf):
    _child_spec = SecurityCategory


class Clearance(Sequence):
    _fields = [
        ('policy_id', ObjectIdentifier),
        ('class_list', ClassList, {'default': set(['unclassified'])}),
        ('security_categories', SetOfSecurityCategory, {'optional': True}),
    ]


class SetOfClearance(SetOf):
    _child_spec = Clearance


class BigTime(Sequence):
    _fields = [
        ('major', Integer),
        ('fractional_seconds', Integer),
        ('sign', Integer, {'optional': True}),
    ]


class LeapData(Sequence):
    _fields = [
        ('leap_time', BigTime),
        ('action', Integer),
    ]


class SetOfLeapData(SetOf):
    _child_spec = LeapData


class TimingMetrics(Sequence):
    _fields = [
        ('ntp_time', BigTime),
        ('offset', BigTime),
        ('delay', BigTime),
        ('expiration', BigTime),
        ('leap_event', SetOfLeapData, {'optional': True}),
    ]


class SetOfTimingMetrics(SetOf):
    _child_spec = TimingMetrics


class TimingPolicy(Sequence):
    _fields = [
        ('policy_id', SequenceOf, {'spec': ObjectIdentifier}),
        ('max_offset', BigTime, {'explicit': 0, 'optional': True}),
        ('max_delay', BigTime, {'explicit': 1, 'optional': True}),
    ]


class SetOfTimingPolicy(SetOf):
    _child_spec = TimingPolicy


class AttCertAttributeType(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.10.1': 'authentication_info',
        '1.3.6.1.5.5.7.10.2': 'access_identity',
        '1.3.6.1.5.5.7.10.3': 'charging_identity',
        '1.3.6.1.5.5.7.10.4': 'group',
        '2.5.4.72': 'role',
        '2.5.4.55': 'clearance',
        '1.3.6.1.4.1.601.10.4.1': 'timing_metrics',
        '1.3.6.1.4.1.601.10.4.2': 'timing_policy',
    }


class AttCertAttribute(Sequence):
    _fields = [
        ('type', AttCertAttributeType),
        ('values', None),
    ]

    _oid_specs = {
        'authentication_info': SetOfSvceAuthInfo,
        'access_identity': SetOfSvceAuthInfo,
        'charging_identity': SetOfIetfAttrSyntax,
        'group': SetOfIetfAttrSyntax,
        'role': SetOfRoleSyntax,
        'clearance': SetOfClearance,
        'timing_metrics': SetOfTimingMetrics,
        'timing_policy': SetOfTimingPolicy,
    }

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class AttCertAttributes(SequenceOf):
    _child_spec = AttCertAttribute


class AttributeCertificateInfoV2(Sequence):
    _fields = [
        ('version', AttCertVersion),
        ('holder', Holder),
        ('issuer', AttCertIssuer),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', AttCertAttributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV2(Sequence):
    # Handle the situation where a V2 cert is encoded as V1
    _bad_tag = 1

    _fields = [
        ('ac_info', AttributeCertificateInfoV2),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class OtherCertificateFormat(Sequence):
    _fields = [
        ('other_cert_format', ObjectIdentifier),
        ('other_cert', Any),
    ]


class CertificateChoices(Choice):
    _alternatives = [
        ('certificate', Certificate),
        ('extended_certificate', ExtendedCertificate, {'implicit': 0}),
        ('v1_attr_cert', AttributeCertificateV1, {'implicit': 1}),
        ('v2_attr_cert', AttributeCertificateV2, {'implicit': 2}),
        ('other', OtherCertificateFormat, {'implicit': 3}),
    ]

    def validate(self, class_, tag, contents):
        """
        Ensures that the class and tag specified exist as an alternative. This
        custom version fixes parsing broken encodings there a V2 attribute
        # certificate is encoded as a V1

        :param class_:
            The integer class_ from the encoded value header

        :param tag:
            The integer tag from the encoded value header

        :param contents:
            A byte string of the contents of the value - used when the object
            is explicitly tagged

        :raises:
            ValueError - when value is not a valid alternative
        """

        super(CertificateChoices, self).validate(class_, tag, contents)
        if self._choice == 2:
            if AttCertVersion.load(Sequence.load(contents)[0].dump()).native == 'v2':
                self._choice = 3


class CertificateSet(SetOf):
    _child_spec = CertificateChoices


class ContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', Any, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class SetOfContentInfo(SetOf):
    _child_spec = ContentInfo


class EncapsulatedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', ParsableOctetString, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class IssuerAndSerialNumber(Sequence):
    _fields = [
        ('issuer', Name),
        ('serial_number', Integer),
    ]


class SignerIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class DigestAlgorithms(SetOf):
    _child_spec = DigestAlgorithm


class CertificateRevocationLists(SetOf):
    _child_spec = CertificateList


class SCVPReqRes(Sequence):
    _fields = [
        ('request', ContentInfo, {'explicit': 0, 'optional': True}),
        ('response', ContentInfo),
    ]


class OtherRevInfoFormatId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.16.2': 'ocsp_response',
        '1.3.6.1.5.5.7.16.4': 'scvp',
    }


class OtherRevocationInfoFormat(Sequence):
    _fields = [
        ('other_rev_info_format', OtherRevInfoFormatId),
        ('other_rev_info', Any),
    ]

    _oid_pair = ('other_rev_info_format', 'other_rev_info')
    _oid_specs = {
        'ocsp_response': OCSPResponse,
        'scvp': SCVPReqRes,
    }


class RevocationInfoChoice(Choice):
    _alternatives = [
        ('crl', CertificateList),
        ('other', OtherRevocationInfoFormat, {'implicit': 1}),
    ]


class RevocationInfoChoices(SetOf):
    _child_spec = RevocationInfoChoice


class SignerInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('sid', SignerIdentifier),
        ('digest_algorithm', DigestAlgorithm),
        ('signed_attrs', CMSAttributes, {'implicit': 0, 'optional': True}),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetString),
        ('unsigned_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class SignerInfos(SetOf):
    _child_spec = SignerInfo


class SignedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithms', DigestAlgorithms),
        ('encap_content_info', None),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class OriginatorInfo(Sequence):
    _fields = [
        ('certs', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
    ]


class RecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class KeyEncryptionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.1.1': 'rsaes_pkcs1v15',
        '1.2.840.113549.1.1.7': 'rsaes_oaep',
        '2.16.840.1.101.3.4.1.5': 'aes128_wrap',
        '2.16.840.1.101.3.4.1.8': 'aes128_wrap_pad',
        '2.16.840.1.101.3.4.1.25': 'aes192_wrap',
        '2.16.840.1.101.3.4.1.28': 'aes192_wrap_pad',
        '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
        '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad',
    }

    _reverse_map = {
        'rsa': '1.2.840.113549.1.1.1',
        'rsaes_pkcs1v15': '1.2.840.113549.1.1.1',
        'rsaes_oaep': '1.2.840.113549.1.1.7',
        'aes128_wrap': '2.16.840.1.101.3.4.1.5',
        'aes128_wrap_pad': '2.16.840.1.101.3.4.1.8',
        'aes192_wrap': '2.16.840.1.101.3.4.1.25',
        'aes192_wrap_pad': '2.16.840.1.101.3.4.1.28',
        'aes256_wrap': '2.16.840.1.101.3.4.1.45',
        'aes256_wrap_pad': '2.16.840.1.101.3.4.1.48',
    }


class KeyEncryptionAlgorithm(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', KeyEncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsaes_oaep': RSAESOAEPParams,
    }


class KeyTransRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('rid', RecipientIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OriginatorIdentifierOrKey(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
        ('originator_key', PublicKeyInfo, {'implicit': 1}),
    ]


class OtherKeyAttribute(Sequence):
    _fields = [
        ('key_attr_id', ObjectIdentifier),
        ('key_attr', Any),
    ]


class RecipientKeyIdentifier(Sequence):
    _fields = [
        ('subject_key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]

    def _setup(self):
        super(RecipientKeyIdentifier, self)._setup()
        # This creates a backwards compatible shim for an
        # incorrect format field name that was in old versions
        self._field_map['subjectKeyIdentifier'] = self._field_map['subject_key_identifier']


class KeyAgreementRecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('r_key_id', RecipientKeyIdentifier, {'implicit': 0}),
    ]


class RecipientEncryptedKey(Sequence):
    _fields = [
        ('rid', KeyAgreementRecipientIdentifier),
        ('encrypted_key', OctetString),
    ]


class RecipientEncryptedKeys(SequenceOf):
    _child_spec = RecipientEncryptedKey


class KeyAgreeRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator', OriginatorIdentifierOrKey, {'explicit': 0}),
        ('ukm', OctetString, {'explicit': 1, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('recipient_encrypted_keys', RecipientEncryptedKeys),
    ]


class KEKIdentifier(Sequence):
    _fields = [
        ('key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]


class KEKRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('kekid', KEKIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class PasswordRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('key_derivation_algorithm', KdfAlgorithm, {'implicit': 0, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OtherRecipientInfo(Sequence):
    _fields = [
        ('ori_type', ObjectIdentifier),
        ('ori_value', Any),
    ]


class RecipientInfo(Choice):
    _alternatives = [
        ('ktri', KeyTransRecipientInfo),
        ('kari', KeyAgreeRecipientInfo, {'implicit': 1}),
        ('kekri', KEKRecipientInfo, {'implicit': 2}),
        ('pwri', PasswordRecipientInfo, {'implicit': 3}),
        ('ori', OtherRecipientInfo, {'implicit': 4}),
    ]


class RecipientInfos(SetOf):
    _child_spec = RecipientInfo


class EncryptedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content_encryption_algorithm', EncryptionAlgorithm),
        ('encrypted_content', OctetString, {'implicit': 0, 'optional': True}),
    ]


class EnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class SignedAndEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('recipient_infos', RecipientInfos),
        ('digest_algorithms', DigestAlgorithms),
        ('encrypted_content_info', EncryptedContentInfo),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', CertificateRevocationLists, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]


class DigestedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithm', DigestAlgorithm),
        ('encap_content_info', None),
        ('digest', OctetString),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class EncryptedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class AuthenticatedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('mac_algorithm', HmacAlgorithm),
        ('digest_algorithm', DigestAlgorithm, {'implicit': 1, 'optional': True}),
        # This does not require the _spec_callbacks approach of SignedData and
        # DigestedData since AuthenticatedData was not part of PKCS#7
        ('encap_content_info', EncapsulatedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 3, 'optional': True}),
    ]


class AuthEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('auth_encrypted_content_info', EncryptedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
    ]


class CompressionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.3.8': 'zlib',
    }


class CompressionAlgorithm(Sequence):
    _fields = [
        ('algorithm', CompressionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class CompressedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('compression_algorithm', CompressionAlgorithm),
        ('encap_content_info', EncapsulatedContentInfo),
    ]

    _decompressed = None

    @property
    def decompressed(self):
        if self._decompressed is None:
            if zlib is None:
                raise SystemError('The zlib module is not available')
            self._decompressed = zlib.decompress(self['encap_content_info']['content'].native)
        return self._decompressed


class SMIMEEncryptionKeyPreference(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber, {'implicit': 0}),
        ('recipient_key_id', RecipientKeyIdentifier, {'implicit': 1}),
        ('subject_alt_key_identifier', PublicKeyInfo, {'implicit': 2}),
    ]

    def _setup(self):
        super(SMIMEEncryptionKeyPreference, self)._setup()
        # This creates backwards compatible shims for two
        # incorrect format alternative names that were in old versions
        self._name_map['recipientKeyId'] = self._name_map['recipient_key_id']
        self._name_map['subjectAltKeyIdentifier'] = self._name_map['subject_alt_key_identifier']


class SMIMEEncryptionKeyPreferences(SetOf):
    _child_spec = SMIMEEncryptionKeyPreference


class SMIMECapabilityIdentifier(Sequence):
    _fields = [
        ('capability_id', EncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class SMIMECapabilites(SequenceOf):
    _child_spec = SMIMECapabilityIdentifier


class SetOfSMIMECapabilites(SetOf):
    _child_spec = SMIMECapabilites


ContentInfo._oid_specs = {
    'data': OctetString,
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


EncapsulatedContentInfo._oid_specs = {
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


CMSAttribute._oid_specs = {
    'content_type': SetOfContentType,
    'message_digest': SetOfOctetString,
    'signing_time': SetOfTime,
    'counter_signature': SignerInfos,
    'signature_time_stamp_token': SetOfContentInfo,
    'cms_algorithm_protection': SetOfCMSAlgorithmProtection,
    'microsoft_nested_signature': SetOfContentInfo,
    'microsoft_time_stamp_token': SetOfContentInfo,
    'encrypt_key_pref': SMIMEEncryptionKeyPreferences,
    'smime_capabilities': SetOfSMIMECapabilites,
}


# The following helpers extract per-SignerInfo verification material from
# SignedData structures, per RFC 5652 section 5. They only prepare the bytes
# and comparisons a signature verifier needs; they never verify signatures.

# Problem codes reported in SignerVerificationMaterial.problems:
#
#  - "missing_content"
#      No encapsulated content was available and no detached content was
#      supplied, so the message digest could not be computed.
#  - "unsupported_digest_algorithm"
#      The digestAlgorithm OID is not one for which a digest can be computed.
#  - "missing_signed_attribute"
#      A required signed attribute ("content_type" or "message_digest") is
#      absent or has no value.
#  - "duplicate_signed_attribute"
#      A signed attribute type occurs more than once in signedAttrs.
#  - "invalid_signed_attribute_value"
#      A required signed attribute has the wrong number of values.
#  - "message_digest_mismatch"
#      The messageDigest signed attribute does not equal the digest of the
#      encapsulated content.
#  - "content_type_mismatch"
#      The contentType signed attribute does not equal the eContentType of the
#      EncapsulatedContentInfo.
#  - "incompatible_algorithms"
#      The signature algorithm embeds a hash (RSA PKCS#1 v1.5 combined OIDs,
#      DSA/ECDSA combined OIDs, RSASSA-PSS params, Ed25519/Ed448) that is
#      incompatible with the SignerInfo digestAlgorithm.

_DIGEST_NAMES = {
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
}

# RFC 8702 - Ed448 uses the 512-bit output of SHAKE256 in CMS
_SHAKE_OUTPUT_SIZES = {
    'shake256': 64,
}


class SignerVerificationMaterial(object):
    """
    Verification material for a single SignerInfo. The values describe what a
    signature verifier needs to check; an empty list of :attr:`problems` only
    means the structure and content checks below passed - the signature value
    itself has not been verified.
    """

    __slots__ = [
        'signer_info',
        'sid',
        'certificate',
        'digest_algorithm',
        'signature_algorithm',
        'signature',
        'encapsulated_content',
        'content_is_detached',
        'has_signed_attrs',
        'verification_input',
        'signed_attrs_der',
        'content_digest',
        'message_digest',
        'content_type_match',
        'problems',
    ]

    def __init__(
        self,
        signer_info,
        sid,
        certificate,
        digest_algorithm,
        signature_algorithm,
        signature,
        encapsulated_content,
        content_is_detached,
        has_signed_attrs,
        verification_input,
        signed_attrs_der,
        content_digest,
        message_digest,
        content_type_match,
        problems,
    ):
        self.signer_info = signer_info
        self.sid = sid
        self.certificate = certificate
        self.digest_algorithm = digest_algorithm
        self.signature_algorithm = signature_algorithm
        self.signature = signature
        self.encapsulated_content = encapsulated_content
        self.content_is_detached = content_is_detached
        self.has_signed_attrs = has_signed_attrs
        self.verification_input = verification_input
        self.signed_attrs_der = signed_attrs_der
        self.content_digest = content_digest
        self.message_digest = message_digest
        self.content_type_match = content_type_match
        self.problems = problems


def _encode_der_length(length):
    if length < 0x80:
        return chr_cls(length)
    parts = []
    while length > 0:
        parts.insert(0, length & 0xFF)
        length >>= 8
    return chr_cls(0x80 | len(parts)) + b''.join(chr_cls(part) for part in parts)


def _signed_attrs_der(signed_attrs):
    """
    Encodes signedAttrs as the value that is signed, per RFC 5652 section 5.4:
    the IMPLICIT [0] tagging is removed and the attributes are encoded as a
    standalone DER SET OF. The original on-the-wire attribute bytes and
    ordering are preserved - this never re-encodes individual attributes.

    :param signed_attrs:
        A CMSAttributes instance parsed from a SignerInfo

    :return:
        A byte string of the DER SET OF that was signed
    """

    contents = signed_attrs.contents
    return b'\x31' + _encode_der_length(len(contents)) + contents


def _encapsulated_content_octets(encap_content_info):
    """
    Returns the raw eContent octets of an EncapsulatedContentInfo/ContentInfo,
    or None when the optional content field is absent (detached).

    :param encap_content_info:
        An EncapsulatedContentInfo or ContentInfo instance

    :return:
        A byte string of the content octets, or None
    """

    content = encap_content_info['content']
    if content is None or isinstance(content, Void):
        return None
    native = content.native
    if isinstance(native, byte_cls):
        return native
    # Non-data content types parse into ASN.1 objects; their raw octets are
    # still the content the digest is computed over.
    return content.contents


def _compute_digest(digest_name, content):
    """
    Computes a content digest, handling the variable-output SHAKE algorithms.

    :param digest_name:
        A unicode string hash name, e.g. "sha256"
    :param content:
        A byte string of the encapsulated content

    :return:
        A byte string of the digest
    """

    if digest_name in _SHAKE_OUTPUT_SIZES:
        hasher = hashlib.new(digest_name)
        hasher.update(content)
        return hasher.digest(_SHAKE_OUTPUT_SIZES[digest_name])
    return hashlib.new(digest_name, content).digest()


def _check_algorithm_compatibility(signer_info):
    """
    Reports signature/digest algorithm combinations that cannot be valid
    together. Combined hash-with-signature OIDs and Ed25519/Ed448 determine a
    required digest; generic rsassa_pkcs1v15/dsa/ecdsa OIDs leave the choice
    to digestAlgorithm and are therefore always compatible.

    :param signer_info:
        A SignerInfo instance

    :return:
        A boolean - True if the combination is compatible (or not known)
    """

    signature_algorithm = signer_info['signature_algorithm']
    digest_name = signer_info['digest_algorithm']['algorithm'].native
    signature_name = signature_algorithm['algorithm'].native
    required_digest = None
    if signature_name in signature_algorithm._algo_map:
        required_digest = signature_algorithm._algo_map[signature_name]
    elif signature_name == 'rsassa_pss':
        required_digest = signature_algorithm['parameters']['hash_algorithm']['algorithm'].native
    elif signature_name in ('ed25519', 'ed448'):
        required_digest = signature_algorithm.cms_hash_algo
    if required_digest is None:
        return True
    return required_digest == digest_name


def extract_signer_verification_material(signed_data, detached_content=None):
    """
    Extracts the material a separate signature verifier needs for each
    SignerInfo in a CMS SignedData structure. This does not verify any
    signature - it only parses the structure, prepares the exact bytes that
    were signed, computes the encapsulated-content digest, and reports
    structural/content discrepancies that make signature verification moot.

    :param signed_data:
        A ContentInfo, SignedData instance, or DER/PEM byte string of either
    :param detached_content:
        Optional byte string of the detached eContent octets

    :raises:
        ValueError - when the input is not a ContentInfo/SignedData, or when
        detached_content is supplied while the structure also carries
        encapsulated content

    :return:
        A list of SignerVerificationMaterial instances, one per SignerInfo
    """

    from . import pem

    if isinstance(signed_data, byte_cls) and not isinstance(signed_data, str_cls):
        data = signed_data
        if b'-----BEGIN ' in data:
            _, _, data = pem.unarmor(data)
        try:
            parsed = ContentInfo.load(data)
        except (ValueError):
            parsed = SignedData.load(data)
        if isinstance(parsed, ContentInfo):
            if parsed['content_type'].native != 'signed_data':
                raise ValueError('ContentInfo does not encapsulate SignedData')
            signed_data = parsed['content']
        else:
            signed_data = parsed
    elif isinstance(signed_data, ContentInfo):
        if signed_data['content_type'].native != 'signed_data':
            raise ValueError('ContentInfo does not encapsulate SignedData')
        signed_data = signed_data['content']
    elif not isinstance(signed_data, SignedData):
        raise ValueError(
            'signed_data must be a ContentInfo, SignedData, or DER/PEM bytes'
        )

    encap_content_info = signed_data['encap_content_info']
    embedded_content = _encapsulated_content_octets(encap_content_info)
    if embedded_content is not None and detached_content is not None:
        raise ValueError(
            'detached_content supplied but the SignedData already contains '
            'encapsulated content'
        )
    if embedded_content is not None:
        content = embedded_content
        content_is_detached = False
    else:
        content = detached_content
        content_is_detached = True

    econtent_type = encap_content_info['content_type'].native

    certificates = []
    certificate_choices = signed_data['certificates']
    if not isinstance(certificate_choices, Void):
        for choice in certificate_choices:
            if choice.name == 'certificate':
                certificates.append(choice.chosen)

    materials = []
    for signer_info in signed_data['signer_infos']:
        problems = []
        digest_algorithm = signer_info['digest_algorithm']
        digest_name = digest_algorithm['algorithm'].native
        hashlib_name = _DIGEST_NAMES.get(digest_name)

        content_digest = None
        if content is None:
            problems.append('missing_content')
        elif hashlib_name is None:
            problems.append('unsupported_digest_algorithm')
        else:
            content_digest = _compute_digest(hashlib_name, content)

        if not _check_algorithm_compatibility(signer_info):
            problems.append('incompatible_algorithms')

        has_signed_attrs = (
            not isinstance(signer_info['signed_attrs'], Void)
        )
        signed_attrs_der = None
        message_digest = None
        content_type_match = None

        if has_signed_attrs:
            signed_attrs = signer_info['signed_attrs']
            signed_attrs_der = _signed_attrs_der(signed_attrs)
            verification_input = signed_attrs_der

            attributes_by_type = {}
            for attribute in signed_attrs:
                attribute_type = attribute['type'].native
                attributes_by_type.setdefault(attribute_type, []).append(attribute)

            for attribute_type, occurrences in attributes_by_type.items():
                if len(occurrences) > 1:
                    problems.append('duplicate_signed_attribute')

            for required_type in ('content_type', 'message_digest'):
                occurrences = attributes_by_type.get(required_type)
                if not occurrences:
                    problems.append('missing_signed_attribute')
                    continue
                values = occurrences[0]['values']
                if len(values) != 1:
                    problems.append('invalid_signed_attribute_value')

            content_type_attributes = attributes_by_type.get('content_type')
            if (
                content_type_attributes and
                len(content_type_attributes) == 1 and
                len(content_type_attributes[0]['values']) == 1
            ):
                signed_content_type = content_type_attributes[0]['values'][0].native
                content_type_match = signed_content_type == econtent_type
                if not content_type_match:
                    problems.append('content_type_mismatch')

            message_digest_attributes = attributes_by_type.get('message_digest')
            if (
                message_digest_attributes and
                len(message_digest_attributes) == 1 and
                len(message_digest_attributes[0]['values']) == 1
            ):
                message_digest = message_digest_attributes[0]['values'][0].native
                if content_digest is not None and message_digest != content_digest:
                    problems.append('message_digest_mismatch')
        else:
            verification_input = content
            if content is None:
                verification_input = None

        certificate = None
        sid = signer_info['sid']
        if sid.name == 'issuer_and_serial_number':
            issuer = sid.chosen['issuer']
            serial_number = sid.chosen['serial_number'].native
            for candidate in certificates:
                if candidate.issuer == issuer and candidate.serial_number == serial_number:
                    certificate = candidate
                    break

        materials.append(SignerVerificationMaterial(
            signer_info=signer_info,
            sid=sid,
            certificate=certificate,
            digest_algorithm=digest_algorithm,
            signature_algorithm=signer_info['signature_algorithm'],
            signature=signer_info['signature'].native,
            encapsulated_content=content,
            content_is_detached=content_is_detached,
            has_signed_attrs=has_signed_attrs,
            verification_input=verification_input,
            signed_attrs_der=signed_attrs_der,
            content_digest=content_digest,
            message_digest=message_digest,
            content_type_match=content_type_match,
            problems=problems,
        ))

    return materials
