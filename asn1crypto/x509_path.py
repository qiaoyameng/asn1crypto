# coding: utf-8

"""
Candidate X.509 certification path construction.

This module builds candidate paths from a leaf certificate through supplied
intermediate certificates to explicit trust anchors. It performs only the
small set of structural checks needed to decide whether an edge may be
considered:

 - issuer distinguished name matches subject distinguished name
 - child authority key identifier matches issuer subject key identifier
   when the child includes a key identifier
 - leaf and issuer certificates are valid at the supplied time
 - issuer certificate has CA basic constraints and keyCertSign when key usage
   is present
 - basic constraints path length is not exceeded
 - the supplied callback verifies the signature

This is intentionally not a complete PKIX certification path validator. Among
other things, it does not implement:

 - CRL or OCSP revocation checking
 - certificate policy, policy mapping, policy constraints or inhibit anyPolicy
 - name constraints
 - extended key usage or key usage bits other than keyCertSign
 - processing or rejection of unrecognized critical extensions
 - signature algorithm, public key algorithm or key strength acceptance
 - authority key identifier matching by authority certificate issuer/serial
 - anchor-specific name, policy or key usage constraints
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from ._types import int_types
from .x509 import Certificate


LIMITATIONS = (
    'revocation checking is not performed',
    'certificate policies, policy mappings, policy constraints and '
    'inhibit anyPolicy are not processed',
    'name constraints are not processed',
    'extended key usage and key usage bits other than keyCertSign are '
    'not processed',
    'unrecognized critical extensions are not processed',
    'signature and public key algorithm acceptability is not checked',
    'authority key identifiers are not matched using authority certificate '
    'issuer and serial number',
    'trust anchor constraints are not applied',
)


class CandidatePathBuilderResult(object):
    """
    The result of a candidate path search.

    :ivar paths:
        A tuple of certificate paths. Each path is a tuple ordered from the
        leaf certificate through intermediate certificates to a trust anchor.
    :ivar incomplete:
        A boolean. ``False`` means the complete finite search space was
        examined. ``True`` means the search stopped after returning
        ``max_paths`` paths and may not have examined the remaining space.
    :ivar max_paths:
        The path limit used for the search.
    """

    __slots__ = ('paths', 'incomplete', 'max_paths')

    def __init__(self, paths, incomplete, max_paths):
        self.paths = tuple(paths)
        self.incomplete = incomplete
        self.max_paths = max_paths


def build_candidate_paths(leaf_certificate, intermediate_certificates,
                          trust_anchors, verification_time,
                          signature_verifier, max_paths=100):
    """
    Build candidate certification paths to explicit trust anchors.

    :param leaf_certificate:
        An :class:`asn1crypto.x509.Certificate` to begin the search from.
    :param intermediate_certificates:
        An iterable of :class:`asn1crypto.x509.Certificate` objects that may be
        used between the leaf and a trust anchor.
    :param trust_anchors:
        An iterable of :class:`asn1crypto.x509.Certificate` objects treated as
        acceptable explicit trust anchors.
    :param verification_time:
        A timezone-aware :class:`datetime.datetime` in UTC to use for validity
        checks.
    :param signature_verifier:
        A callable accepting ``(child_certificate, issuer_certificate)`` and
        returning a truthy value only when the child's signature validates with
        the issuer's public key. It must be deterministic and side-effect free.
    :param max_paths:
        A positive integer limiting the number of returned paths.

    :return:
        A :class:`CandidatePathBuilderResult`.
    """

    _require_certificate(leaf_certificate, 'leaf_certificate')
    if not isinstance(verification_time, datetime):
        raise TypeError(
            'verification_time must be a datetime.datetime object'
        )
    if verification_time.tzinfo is None:
        raise ValueError('verification_time must be timezone aware')
    if not callable(signature_verifier):
        raise TypeError('signature_verifier must be callable')
    if (not isinstance(max_paths, int_types)
            or isinstance(max_paths, bool) or max_paths < 1):
        raise ValueError('max_paths must be a positive integer')

    if not _valid_at(leaf_certificate, verification_time):
        return CandidatePathBuilderResult((), False, max_paths)

    anchors = _deduplicate_certificates(trust_anchors, 'trust_anchors')
    candidates = _deduplicate_certificates(
        intermediate_certificates, 'intermediate_certificates'
    )

    anchor_ids = set(certificate.sha256 for certificate in anchors)
    anchor_ids.discard(leaf_certificate.sha256)

    all_certificates = {}
    for certificate in anchors + candidates:
        all_certificates[certificate.sha256] = certificate
    all_certificates[leaf_certificate.sha256] = leaf_certificate

    parents_by_subject = {}
    sorted_certificates = sorted(
        all_certificates.values(), key=lambda item: item.sha256
    )
    for certificate in sorted_certificates:
        parents_by_subject.setdefault(
            certificate.subject.hashable, []
        ).append(certificate)

    verified_edges = {}
    completed_paths = []

    def search(current_path):
        current_certificate = current_path[-1]
        current_id = current_certificate.sha256

        if current_id in anchor_ids:
            completed_paths.append(tuple(current_path))
            return len(completed_paths) >= max_paths

        path_ids = set(certificate.sha256 for certificate in current_path)
        issuers = parents_by_subject.get(
            current_certificate.issuer.hashable, ()
        )
        for issuer_certificate in issuers:
            issuer_id = issuer_certificate.sha256
            if issuer_id in path_ids:
                continue
            if not _is_possible_issuer(current_certificate, issuer_certificate,
                                       verification_time, current_path):
                continue

            edge_key = (current_id, issuer_id)
            if edge_key not in verified_edges:
                verified_edges[edge_key] = bool(
                    signature_verifier(current_certificate, issuer_certificate)
                )
            if not verified_edges[edge_key]:
                continue

            if search(current_path + [issuer_certificate]):
                return True

        return False

    incomplete = search([leaf_certificate])
    return CandidatePathBuilderResult(completed_paths, incomplete, max_paths)


def _deduplicate_certificates(certificates, argument_name):
    try:
        materialized = list(certificates)
    except TypeError:
        raise TypeError('%s must be iterable' % argument_name)

    by_identity = {}
    for certificate in materialized:
        _require_certificate(certificate, argument_name)
        by_identity.setdefault(certificate.sha256, certificate)
    return list(by_identity.values())


def _require_certificate(certificate, argument_name):
    if not isinstance(certificate, Certificate):
        raise TypeError('%s must contain x509.Certificate objects' % argument_name)


def _is_possible_issuer(child_certificate, issuer_certificate,
                        verification_time, path):
    if child_certificate.issuer != issuer_certificate.subject:
        return False

    child_aki = child_certificate.authority_key_identifier
    issuer_ski = issuer_certificate.key_identifier
    if child_aki is not None and child_aki != issuer_ski:
        return False

    if not _valid_at(issuer_certificate, verification_time):
        return False

    if not _is_ca(issuer_certificate) or not _has_key_cert_sign(
            issuer_certificate):
        return False

    max_path_length = issuer_certificate.max_path_length
    if max_path_length is not None:
        intermediate_count = 0
        for certificate in path:
            if certificate is path[0] or certificate.self_issued:
                continue
            intermediate_count += 1
        if intermediate_count > max_path_length:
            return False

    return True


def _valid_at(certificate, verification_time):
    return (
        certificate.not_valid_before <= verification_time
        and verification_time <= certificate.not_valid_after
    )


def _is_ca(certificate):
    basic_constraints = certificate.basic_constraints_value
    return bool(basic_constraints and basic_constraints['ca'].native)


def _has_key_cert_sign(certificate):
    key_usage = certificate.key_usage_value
    return key_usage is None or 'key_cert_sign' in key_usage.native
