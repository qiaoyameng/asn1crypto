# coding: utf-8

"""
Pure data-layer evaluation of CRL applicability and revocation-reason
coverage. Exports the following items:

 - ALL_REASONS
 - CRLAssessment()
 - RevocationEvaluation()
 - evaluate_revocation()

The evaluator answers a single question: given a certificate, a set of CRLs
that the caller has already authenticated (signature verified against a
trusted issuer key), and an explicit point in time, do the CRLs together
provide complete revocation coverage for the certificate, and is the
certificate listed as revoked on any of them?

Coverage is determined by correlating the certificate's
CRLDistributionPoints extension with each CRL's IssuingDistributionPoint
extension, honoring only_some_reasons, only_contains_user_certs,
only_contains_ca_certs, only_contains_attribute_certs and indirect_crl, as
described in RFC 5280. Multiple CRLs may complement each other, each
covering a different partition of the reason codes. A status of "good" is
only returned when every reason code is covered by at least one applicable,
time-valid CRL.

This layer performs no network I/O (it never downloads CRLs) and no
cryptography (it never verifies signatures). Expired, not-yet-valid or
name-mismatched CRLs are reported as unusable and can never contribute to
a positive conclusion.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
from ._types import type_name
from .crl import CertificateList
from .x509 import Certificate, ReasonFlags


__all__ = [
    'ALL_REASONS',
    'CRLAssessment',
    'RevocationEvaluation',
    'evaluate_revocation',
]


# The full set of revocation reason codes that must be covered for a
# conclusive "good" answer. The ReasonFlags bit "unused" is padding, not a
# reason, so it is excluded.
ALL_REASONS = frozenset(
    reason for reason in ReasonFlags._map.values() if reason != 'unused'
)


class CRLAssessment(object):
    """
    The per-CRL result of evaluating applicability and coverage
    """

    # The asn1crypto.crl.CertificateList object that was assessed
    crl = None

    # A bool - if the CRL is time-valid, correctly named and in scope for
    # the certificate
    applicable = None

    # A tuple of unicode strings - machine-readable codes describing why
    # the CRL can not be used, e.g. "expired", "issuer_mismatch",
    # "scope_mismatch", "distribution_point_mismatch"
    problems = None

    # A bool - if the CRL is a delta CRL. Delta CRLs only describe changes
    # relative to a base CRL, so they never contribute reason coverage on
    # their own, although their revocation entries are still honored.
    is_delta = None

    # A frozenset of unicode strings - the reason codes this CRL vouches
    # for. Empty when the CRL is not applicable or is a delta CRL.
    covered_reasons = None

    def __init__(self, crl, applicable, problems, is_delta, covered_reasons):
        self.crl = crl
        self.applicable = applicable
        self.problems = problems
        self.is_delta = is_delta
        self.covered_reasons = covered_reasons

    def __repr__(self):
        return '<%s(applicable=%r, problems=%r, covered_reasons=%r)>' % (
            self.__class__.__name__,
            self.applicable,
            self.problems,
            sorted(self.covered_reasons),
        )


class RevocationEvaluation(object):
    """
    The aggregate result of evaluating a certificate against a set of CRLs
    """

    # The asn1crypto.x509.Certificate object that was evaluated
    certificate = None

    # The datetime the evaluation was performed for
    moment = None

    # A tuple of CRLAssessment objects, one per CRL provided
    assessments = None

    # A unicode string - one of "good", "revoked" or "unknown". "good" is
    # only possible when every reason code is covered by at least one
    # applicable CRL. "unknown" means coverage is incomplete - the
    # certificate may be revoked under a reason no usable CRL covers.
    status = None

    # A frozenset of unicode strings - union of covered reason codes over
    # all applicable CRLs
    covered_reasons = None

    # A frozenset of unicode strings - ALL_REASONS minus covered_reasons
    missing_reasons = None

    # None, or a datetime of when the certificate was revoked
    revocation_date = None

    # None, or a unicode string of the CRLReason name for the revocation
    revocation_reason = None

    # None, or an asn1crypto.x509.Name of the issuer of the CRL that lists
    # the certificate as revoked
    revoking_crl_issuer = None

    def __init__(self, certificate, moment, assessments, status,
                 covered_reasons, missing_reasons, revocation_date=None,
                 revocation_reason=None, revoking_crl_issuer=None):
        self.certificate = certificate
        self.moment = moment
        self.assessments = assessments
        self.status = status
        self.covered_reasons = covered_reasons
        self.missing_reasons = missing_reasons
        self.revocation_date = revocation_date
        self.revocation_reason = revocation_reason
        self.revoking_crl_issuer = revoking_crl_issuer

    def __repr__(self):
        return '<%s(status=%r, missing_reasons=%r)>' % (
            self.__class__.__name__,
            self.status,
            sorted(self.missing_reasons),
        )


def _distribution_point_names_match(cert_dp_name, idp_dp_name):
    """
    Compares a DistributionPointName from the certificate's
    CRLDistributionPoints extension with one from a CRL's
    IssuingDistributionPoint extension

    :param cert_dp_name:
        An asn1crypto.x509.DistributionPointName from the certificate

    :param idp_dp_name:
        An asn1crypto.x509.DistributionPointName from the CRL

    :return:
        A boolean
    """

    if cert_dp_name.name != idp_dp_name.name:
        return False

    if cert_dp_name.name == 'full_name':
        # A match on any single general name is sufficient
        cert_names = set(general_name.dump() for general_name in cert_dp_name.chosen)
        idp_names = set(general_name.dump() for general_name in idp_dp_name.chosen)
        return bool(cert_names & idp_names)

    return cert_dp_name.chosen.dump() == idp_dp_name.chosen.dump()


def _general_names_contain(general_names, name):
    """
    Checks if a GeneralNames structure contains a directoryName equal to an
    x509.Name

    :param general_names:
        An asn1crypto.x509.GeneralNames object

    :param name:
        An asn1crypto.x509.Name object

    :return:
        A boolean
    """

    for general_name in general_names:
        if general_name.name == 'directory_name' and general_name.chosen == name:
            return True
    return False


def _assess_crl(certificate, crl, moment):
    """
    Determines if a CRL is applicable to a certificate at a moment in time,
    and which revocation reason codes it covers

    :param certificate:
        An asn1crypto.x509.Certificate object

    :param crl:
        An asn1crypto.crl.CertificateList object

    :param moment:
        A timezone-aware datetime object

    :return:
        A CRLAssessment object
    """

    problems = []
    tbs = crl['tbs_cert_list']

    this_update = tbs['this_update'].native
    next_update = tbs['next_update'].native
    if this_update is not None and moment < this_update:
        problems.append('not_yet_valid')
    if next_update is not None and moment > next_update:
        problems.append('expired')

    idp = crl.issuing_distribution_point_value

    # Scope restrictions from the issuing distribution point
    if idp is not None:
        if idp['only_contains_attribute_certs'].native:
            problems.append('only_contains_attribute_certs')
        is_ca_cert = bool(certificate.ca)
        if idp['only_contains_user_certs'].native and is_ca_cert:
            problems.append('only_contains_user_certs')
        if idp['only_contains_ca_certs'].native and not is_ca_cert:
            problems.append('only_contains_ca_certs')

    # Correlate the CRL's distribution point with the certificate's
    idp_dp_name = None
    if idp is not None and idp['distribution_point'].native is not None:
        idp_dp_name = idp['distribution_point']

    matched_dp = None
    if idp_dp_name is not None:
        cert_dps = certificate.crl_distribution_points_value
        if cert_dps is not None:
            for cert_dp in cert_dps:
                cert_dp_name = cert_dp['distribution_point']
                if cert_dp_name.native is None:
                    continue
                if _distribution_point_names_match(cert_dp_name, idp_dp_name):
                    matched_dp = cert_dp
                    break
        if matched_dp is None:
            problems.append('distribution_point_mismatch')

    # Issuer name checks - indirect CRLs are issued by a name taken from
    # the certificate's distribution point, direct CRLs by the cert issuer
    indirect = idp is not None and bool(idp['indirect_crl'].native)
    if indirect:
        crl_issuer_names = None
        if matched_dp is not None and matched_dp['crl_issuer'].native is not None:
            crl_issuer_names = matched_dp['crl_issuer']
        if crl_issuer_names is None:
            problems.append('indirect_crl_issuer_unknown')
        elif not _general_names_contain(crl_issuer_names, crl.issuer):
            problems.append('issuer_mismatch')
    else:
        if crl.issuer != certificate.issuer:
            problems.append('issuer_mismatch')

    is_delta = crl.delta_crl_indicator_value is not None

    covered_reasons = frozenset()
    if not problems and not is_delta:
        if idp is not None and idp['only_some_reasons'].native:
            covered = set(idp['only_some_reasons'].native) & ALL_REASONS
        else:
            covered = set(ALL_REASONS)
        # The certificate's distribution point may itself restrict reasons
        if matched_dp is not None and matched_dp['reasons'].native:
            covered &= set(matched_dp['reasons'].native)
        covered_reasons = frozenset(covered)

    return CRLAssessment(
        crl=crl,
        applicable=not problems,
        problems=tuple(problems),
        is_delta=is_delta,
        covered_reasons=covered_reasons,
    )


def _find_revocation(certificate, crl, indirect):
    """
    Searches an applicable CRL for an entry naming the certificate

    :param certificate:
        An asn1crypto.x509.Certificate object

    :param crl:
        An asn1crypto.crl.CertificateList object

    :param indirect:
        A boolean - if the CRL is an indirect CRL

    :return:
        None or an asn1crypto.crl.RevokedCertificate object
    """

    serial_number = certificate.serial_number

    # On an indirect CRL, entries are grouped by certificate issuer; the
    # certificate_issuer entry extension redefines the issuer for the
    # entry it appears on and all subsequent entries
    current_issuer = crl.issuer

    for entry in crl['tbs_cert_list']['revoked_certificates']:
        entry_issuer = entry.certificate_issuer_value
        if entry_issuer is not None:
            for general_name in entry_issuer:
                if general_name.name == 'directory_name':
                    current_issuer = general_name.chosen
                    break

        if entry['user_certificate'].native != serial_number:
            continue

        if indirect and current_issuer != certificate.issuer:
            continue

        return entry

    return None


def evaluate_revocation(certificate, crls, moment):
    """
    Evaluates the revocation status of a certificate against a set of CRLs
    at an explicit moment in time.

    The caller is responsible for having verified the signature of each
    CRL (and of the certificate's chain) before calling - this function
    performs purely data-layer reasoning and never downloads CRLs or
    verifies signatures.

    :param certificate:
        An asn1crypto.x509.Certificate object

    :param crls:
        An iterable of asn1crypto.crl.CertificateList objects, each with
        its signature already verified by the caller

    :param moment:
        A timezone-aware datetime object of when the evaluation is for

    :raises:
        TypeError - when a parameter is of the wrong type
        ValueError - when moment is not timezone-aware

    :return:
        A RevocationEvaluation object. The status is "revoked" if the
        certificate is listed on any applicable CRL, "good" if the
        applicable CRLs together cover every revocation reason code, and
        "unknown" otherwise.
    """

    if not isinstance(certificate, Certificate):
        raise TypeError(unwrap(
            '''
            certificate must be an asn1crypto.x509.Certificate object, not
            %s
            ''',
            type_name(certificate)
        ))

    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(unwrap(
            '''
            moment must be a timezone-aware datetime object
            '''
        ))

    crls = list(crls)
    for crl in crls:
        if not isinstance(crl, CertificateList):
            raise TypeError(unwrap(
                '''
                crls must contain only asn1crypto.crl.CertificateList
                objects, not %s
                ''',
                type_name(crl)
            ))

    assessments = []
    covered_reasons = set()
    revoked_entry = None
    revoked_assessment = None

    for crl in crls:
        assessment = _assess_crl(certificate, crl, moment)
        assessments.append(assessment)

        if not assessment.applicable:
            continue

        covered_reasons |= assessment.covered_reasons

        if revoked_entry is None:
            indirect = crl.issuing_distribution_point_value is not None and \
                bool(crl.issuing_distribution_point_value['indirect_crl'].native)
            entry = _find_revocation(certificate, crl, indirect)
            if entry is not None:
                revoked_entry = entry
                revoked_assessment = assessment

    covered_reasons = frozenset(covered_reasons)
    missing_reasons = ALL_REASONS - covered_reasons

    if revoked_entry is not None:
        crl_reason = revoked_entry.crl_reason_value
        return RevocationEvaluation(
            certificate=certificate,
            moment=moment,
            assessments=tuple(assessments),
            status='revoked',
            covered_reasons=covered_reasons,
            missing_reasons=missing_reasons,
            revocation_date=revoked_entry['revocation_date'].native,
            revocation_reason=crl_reason.native if crl_reason is not None else 'unspecified',
            revoking_crl_issuer=revoked_assessment.crl.issuer,
        )

    status = 'good' if not missing_reasons else 'unknown'

    return RevocationEvaluation(
        certificate=certificate,
        moment=moment,
        assessments=tuple(assessments),
        status=status,
        covered_reasons=covered_reasons,
        missing_reasons=missing_reasons,
    )
