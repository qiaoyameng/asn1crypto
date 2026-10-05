# coding: utf-8

"""
Pure data-layer CRL applicability and coverage determination. Exports the
following items:

 - ALL_REVOCATION_REASONS
 - CRLCoverageAssessment()
 - assess_crl_coverage()

The functions in this module operate exclusively on already-parsed,
already-signature-verified certificates and CRLs supplied by the caller.
No network access is performed and no cryptographic verification is done -
the caller is responsible for downloading CRLs, verifying CRL signatures
and validating the certification path before consulting this module.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .core import Choice, Void
from .util import timezone


# The complete set of revocation reason names from RFC 5280 ReasonFlags
ALL_REVOCATION_REASONS = frozenset([
    'unused',
    'key_compromise',
    'ca_compromise',
    'affiliation_changed',
    'superseded',
    'cessation_of_operation',
    'certificate_hold',
    'privilege_withdrawn',
    'aa_compromise',
])


class CRLCoverageAssessment(object):
    """
    The result of assessing a set of CRLs against a certificate at a
    specific moment in time
    """

    # One of the unicode strings "good", "revoked" or "unknown". "good" is
    # only ever returned when the supplied CRLs provide complete coverage of
    # every revocation reason relevant to the certificate.
    status = None

    # A frozenset of unicode strings of revocation reason names that the
    # applicable CRLs collectively cover for the certificate
    covered_reasons = None

    # A frozenset of unicode strings of revocation reason names that are
    # relevant to the certificate but not covered by any applicable CRL
    missing_reasons = None

    # None, or a unicode string of the CRLReason of the revocation entry
    revocation_reason = None

    # None, or a datetime object of when the certificate was revoked
    revocation_date = None

    # None, or the crl.CertificateList object containing the revocation entry
    revoking_crl = None

    # A tuple of crl.CertificateList objects that were applicable to the
    # certificate at the assessment moment and contributed to coverage
    applicable_crls = None

    def __init__(self, status, covered_reasons, missing_reasons, applicable_crls,
                 revocation_reason=None, revocation_date=None, revoking_crl=None):
        self.status = status
        self.covered_reasons = frozenset(covered_reasons)
        self.missing_reasons = frozenset(missing_reasons)
        self.applicable_crls = tuple(applicable_crls)
        self.revocation_reason = revocation_reason
        self.revocation_date = revocation_date
        self.revoking_crl = revoking_crl

    def __repr__(self):
        return '<CRLCoverageAssessment status=%s, covered=%s, missing=%s>' % (
            self.status,
            sorted(self.covered_reasons),
            sorted(self.missing_reasons),
        )


def _normalize_moment(moment):
    """
    :param moment:
        A datetime object - naive datetimes are assumed to be UTC

    :return:
        A timezone-aware datetime object
    """

    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _required_reasons(certificate):
    """
    Determines the revocation reasons that must be covered by CRLs before a
    "good" conclusion may be reached for a certificate. If the certificate
    contains CRL distribution points that restrict the reasons they cover,
    only the union of those reasons is required - otherwise all reasons.

    :param certificate:
        An asn1crypto.x509.Certificate object

    :return:
        A set of unicode strings of revocation reason names
    """

    distribution_points = certificate.crl_distribution_points_value
    if distribution_points is None:
        return set(ALL_REVOCATION_REASONS)

    required = set()
    for distribution_point in distribution_points:
        reasons = distribution_point['reasons']
        if isinstance(reasons, Void):
            required |= ALL_REVOCATION_REASONS
        else:
            required |= set(reasons.native)
    return required


def _crl_coverage_scope(certificate, crl, moment):
    """
    Determines if a CRL is applicable to a certificate at a moment in time,
    and if so, which revocation reasons it covers. A CRL provides no
    information for a certificate if it is expired or not yet valid, if its
    issuer name does not match (for non-indirect CRLs), if its issuing
    distribution point excludes the certificate type, or if its issuing
    distribution point name does not match a distribution point of the
    certificate.

    :param certificate:
        An asn1crypto.x509.Certificate object

    :param crl:
        An asn1crypto.crl.CertificateList object

    :param moment:
        A timezone-aware datetime object

    :return:
        None if the CRL is not applicable, otherwise a tuple of a set of
        unicode strings of covered revocation reason names and a boolean
        indicating if the CRL is an indirect CRL
    """

    tbs_cert_list = crl['tbs_cert_list']

    # An expired or not-yet-valid CRL can not provide a positive conclusion
    if moment < tbs_cert_list['this_update'].native:
        return None
    next_update = tbs_cert_list['next_update']
    if not isinstance(next_update, Void) and moment > next_update.native:
        return None

    covered_reasons = set(ALL_REVOCATION_REASONS)
    indirect_crl = False

    issuing_distribution_point = crl.issuing_distribution_point_value
    if issuing_distribution_point is not None:
        # Attribute certificates are out of scope for X.509 public key certs
        if issuing_distribution_point['only_contains_attribute_certs'].native:
            return None
        if issuing_distribution_point['only_contains_user_certs'].native and certificate.ca:
            return None
        if issuing_distribution_point['only_contains_ca_certs'].native and not certificate.ca:
            return None

        only_some_reasons = issuing_distribution_point['only_some_reasons']
        if not isinstance(only_some_reasons, Void):
            covered_reasons = set(only_some_reasons.native)

        indirect_crl = bool(issuing_distribution_point['indirect_crl'].native)

        idp_name = issuing_distribution_point['distribution_point']
        if not isinstance(idp_name, Void):
            # The CRL is scoped to a specific distribution point, which must
            # match one of the distribution points of the certificate
            distribution_points = certificate.crl_distribution_points_value
            if distribution_points is None:
                return None
            matched = False
            for distribution_point in distribution_points:
                dp_name = distribution_point['distribution_point']
                if isinstance(dp_name, Void):
                    continue
                if dp_name.dump() != idp_name.dump():
                    continue
                matched = True
                dp_reasons = distribution_point['reasons']
                if not isinstance(dp_reasons, Void):
                    covered_reasons &= set(dp_reasons.native)
                break
            if not matched:
                return None

    # For a direct CRL, the CRL issuer name must match the certificate
    # issuer name. For an indirect CRL, entries are matched individually
    # via the certificate issuer entry extension instead.
    if not indirect_crl:
        if _name_fingerprint(crl.issuer) != _name_fingerprint(certificate.issuer):
            return None

    return (covered_reasons, indirect_crl)


def _name_fingerprint(name):
    """
    Normalizes an asn1crypto.x509.Name object for comparison. A Name that
    was parsed out of a GeneralName directory name carries the implicit
    [4] tag of the enclosing choice, so the DER of the chosen alternative
    is compared instead of the DER of the Name object itself.

    :param name:
        An asn1crypto.x509.Name object

    :return:
        A byte string
    """

    if isinstance(name, Choice):
        return name.chosen.dump()
    return name.dump()


def _entry_issuer_names_match(entry_issuer, certificate_issuer):
    """
    :param entry_issuer:
        None, or an asn1crypto.x509.Name object

    :param certificate_issuer:
        An asn1crypto.x509.Name object

    :return:
        A boolean
    """

    if entry_issuer is None:
        return False
    return _name_fingerprint(entry_issuer) == _name_fingerprint(certificate_issuer)


def _find_revocation(certificate, crl, indirect_crl):
    """
    Searches a CRL for an entry revoking a certificate. For indirect CRLs,
    the certificate issuer entry extension is tracked to determine which
    entries apply to the issuer of the certificate.

    :param certificate:
        An asn1crypto.x509.Certificate object

    :param crl:
        An asn1crypto.crl.CertificateList object

    :param indirect_crl:
        A boolean - if the CRL is an indirect CRL

    :return:
        None, or the matching asn1crypto.crl.RevokedCertificate object
    """

    serial_number = certificate.serial_number
    certificate_issuer = certificate.issuer

    # Entries without a certificate issuer extension belong to the most
    # recently seen issuer, which starts as the CRL issuer
    current_issuer = crl.issuer

    for entry in crl['tbs_cert_list']['revoked_certificates']:
        entry_issuer = entry.issuer_name
        if entry_issuer is not None:
            current_issuer = entry_issuer

        if entry['user_certificate'].native != serial_number:
            continue

        if indirect_crl or entry_issuer is not None:
            if not _entry_issuer_names_match(current_issuer, certificate_issuer):
                continue

        return entry

    return None


def assess_crl_coverage(certificate, crls, moment):
    """
    Determines the revocation status of a certificate from a set of CRLs at
    an explicit moment in time. All CRLs must have already had their
    signatures verified by the caller - this function performs no
    cryptographic verification and no network access.

    A status of "good" is only returned when the applicable CRLs
    collectively cover every revocation reason relevant to the certificate.
    Multiple CRLs may each cover a subset of reasons (via the issuing
    distribution point only_some_reasons extension) and combine to provide
    complete coverage. Expired CRLs and CRLs whose issuer name or issuing
    distribution point does not match the certificate are ignored, and can
    not contribute to a positive conclusion.

    :param certificate:
        An asn1crypto.x509.Certificate object that has already been
        signature-verified by the caller

    :param crls:
        An iterable of asn1crypto.crl.CertificateList objects that have
        already been signature-verified by the caller

    :param moment:
        A datetime object of the time to assess the status at - naive
        datetimes are assumed to be UTC

    :return:
        A CRLCoverageAssessment object
    """

    moment = _normalize_moment(moment)
    required_reasons = _required_reasons(certificate)

    covered_reasons = set()
    applicable_crls = []
    revocation_entry = None
    revoking_crl = None

    for crl in crls:
        scope = _crl_coverage_scope(certificate, crl, moment)
        if scope is None:
            continue

        crl_reasons, indirect_crl = scope

        entry = _find_revocation(certificate, crl, indirect_crl)
        if entry is not None:
            reason = entry.crl_reason_value
            # A remove_from_crl entry on a delta CRL indicates the
            # certificate is no longer revoked, not that it is revoked
            if reason is None or reason.native != 'remove_from_crl':
                revocation_entry = entry
                revoking_crl = crl
                break

        # A delta CRL only describes changes since a base CRL, so on its
        # own it can never provide complete coverage
        if crl.delta_crl_indicator_value is not None:
            continue

        covered_reasons |= crl_reasons
        applicable_crls.append(crl)

    if revocation_entry is not None:
        reason = revocation_entry.crl_reason_value
        return CRLCoverageAssessment(
            status='revoked',
            covered_reasons=covered_reasons,
            missing_reasons=required_reasons - covered_reasons,
            applicable_crls=applicable_crls,
            revocation_reason=reason.native if reason is not None else 'unspecified',
            revocation_date=revocation_entry['revocation_date'].native,
            revoking_crl=revoking_crl,
        )

    missing_reasons = required_reasons - covered_reasons
    status = 'good' if not missing_reasons else 'unknown'

    return CRLCoverageAssessment(
        status=status,
        covered_reasons=covered_reasons,
        missing_reasons=missing_reasons,
        applicable_crls=applicable_crls,
    )
