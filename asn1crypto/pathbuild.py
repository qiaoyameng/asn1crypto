# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .x509 import Certificate


__all__ = [
    'PathBuildResult',
    'PathBuilder',
    'UNIMPLEMENTED_PKIX_FEATURES',
]


# This module is a candidate certification path *builder*, not a full PKIX
# (RFC 5280 section 6) validator. The following parts of full path validation
# are intentionally not implemented and are left to the caller:
UNIMPLEMENTED_PKIX_FEATURES = (
    # certificatePolicies / policyMappings / policyConstraints /
    # inhibitAnyPolicy processing, including the policy tree
    'certificate_policies',
    'policy_mappings',
    'policy_constraints',
    'inhibit_any_policy',
    # permitted/excluded subtrees from the nameConstraints extension
    'name_constraints',
    # revocation checking via CRLs, delta CRLs or OCSP
    'revocation',
    # extendedKeyUsage and anyPurpose evaluation
    'extended_key_usage',
    # authorityKeyIdentifier authority_cert_issuer/authority_cert_serial_number
    # matching (only the key_identifier form is matched)
    'aki_issuer_serial_matching',
    # signature algorithm/parameters suitability and key strength checks
    'algorithm_strength',
    # privateKeyUsagePeriod and other non-chain-shaping extensions
    'private_key_usage_period',
)


class PathBuildResult(object):
    """
    The outcome of PathBuilder.build().

    Attributes:

     - paths - a list of tuples of asn1crypto.x509.Certificate objects. Each
       tuple is a complete candidate path, ordered leaf-first and ending with
       one of the explicitly supplied trust anchors.
     - exhausted - a boolean that is True only when the search space was
       fully explored. If any search limit (max_paths, max_depth,
       max_edge_checks) stopped the search early, this is False, meaning
       additional paths may exist.
    """

    def __init__(self, paths, exhausted):
        self.paths = paths
        self.exhausted = exhausted

    def __repr__(self):
        return '<PathBuildResult paths=%d exhausted=%r>' % (len(self.paths), self.exhausted)


class PathBuilder(object):
    """
    Builds candidate certification paths from a leaf certificate to explicit
    trust anchors, exploring all cross-signing variants instead of stopping
    at the first issuer-name match.

    Matching between a child certificate and a candidate issuer uses:

     - issuer/subject distinguished name equality
     - the child's authorityKeyIdentifier key_identifier against the
       candidate's subjectKeyIdentifier (when the child carries an AKI
       key_identifier, candidates without a matching SKI are rejected, which
       disambiguates same-name-different-key issuers)
     - validity of every certificate at a fixed caller-supplied moment
     - basicConstraints CA=True on every issuer
     - keyUsage keyCertSign on every issuer that carries a keyUsage extension
     - basicConstraints pathLenConstraint against the number of
       non-self-issued CA certificates below the issuer

    Signature verification is delegated to a pure caller-supplied callback,
    verify_signature(issuer_cert, subject_cert) -> bool. Edges for which the
    callback returns False are never used in a path.

    Certificates are deduplicated by their full DER encoding, so distinct
    certificates sharing a subject name (e.g. re-keyed or cross-signed CAs)
    are all explored. Self-issued intermediates are allowed, and loops are
    prevented by never revisiting a certificate identity within one path.

    Candidate issuers are visited in a canonical order (sorted by DER
    encoding), so the returned path order does not depend on the order of
    the input candidate lists.

    This is not a full PKIX validator - see UNIMPLEMENTED_PKIX_FEATURES.
    """

    def __init__(self, verify_signature, max_paths=32, max_depth=10,
                 max_edge_checks=1000):
        """
        :param verify_signature:
            A pure callable taking (issuer_certificate, subject_certificate)
            asn1crypto.x509.Certificate objects and returning a bool - True
            if the subject's signature verifies with the issuer's key. It
            must have no side effects and return the same result for the
            same inputs, since it may be called repeatedly.

        :param max_paths:
            Maximum number of complete paths to collect before stopping.

        :param max_depth:
            Maximum number of certificates in a single path, including the
            leaf and the trust anchor.

        :param max_edge_checks:
            Maximum number of candidate issuer edges to evaluate before
            stopping.
        """

        self._verify_signature = verify_signature
        self._max_paths = max_paths
        self._max_depth = max_depth
        self._max_edge_checks = max_edge_checks

    def build(self, leaf, intermediates, trust_anchors, moment):
        """
        :param leaf:
            An asn1crypto.x509.Certificate of the end-entity certificate.

        :param intermediates:
            An iterable of asn1crypto.x509.Certificate objects to use as
            candidate intermediate CAs. Order is irrelevant.

        :param trust_anchors:
            An iterable of asn1crypto.x509.Certificate objects that are
            explicitly trusted. A path is complete when it reaches one of
            these. Order is irrelevant.

        :param moment:
            A timezone-aware datetime.datetime at which every certificate in
            a path must be within its validity period.

        :return:
            A PathBuildResult.
        """

        if not isinstance(leaf, Certificate):
            raise TypeError('leaf must be an asn1crypto.x509.Certificate')

        # Deduplicate by full certificate identity (DER encoding) and sort
        # into a canonical order so results are independent of input order.
        anchors = _canonicalize(trust_anchors)
        candidates = _canonicalize(list(intermediates) + list(anchors.values()))

        paths = []
        state = {
            'exhausted': True,
            'edge_checks': 0,
        }

        if not _is_valid_at(leaf, moment):
            return PathBuildResult(paths, True)

        self._search(leaf, [leaf], set([leaf.dump()]), candidates, anchors,
                     moment, paths, state)

        return PathBuildResult(paths, state['exhausted'])

    def _search(self, current, chain, in_chain, candidates, anchors,
                moment, paths, state):
        if len(paths) >= self._max_paths:
            state['exhausted'] = False
            return

        if len(chain) >= self._max_depth:
            state['exhausted'] = False
            return

        for issuer_der, issuer in candidates.items():
            if len(paths) >= self._max_paths:
                state['exhausted'] = False
                return

            if state['edge_checks'] >= self._max_edge_checks:
                state['exhausted'] = False
                return

            if issuer_der in in_chain:
                # Prevents loops, including self-signed certificates
                # chaining to themselves.
                continue

            if not _names_match(current, issuer):
                continue

            state['edge_checks'] += 1

            if not _key_identifiers_match(current, issuer):
                continue
            if not _is_valid_at(issuer, moment):
                continue
            if not _is_proper_issuer(issuer, chain):
                continue
            if not self._verify_signature(issuer, current):
                continue

            if issuer_der in anchors:
                paths.append(tuple(chain) + (issuer,))
                continue

            in_chain.add(issuer_der)
            chain.append(issuer)
            self._search(issuer, chain, in_chain, candidates, anchors,
                         moment, paths, state)
            chain.pop()
            in_chain.discard(issuer_der)


def _canonicalize(certificates):
    """
    Deduplicates certificates by full DER identity and returns a dict of
    DER byte string -> Certificate, sorted by DER for deterministic
    traversal order.
    """

    by_der = {}
    for cert in certificates:
        if not isinstance(cert, Certificate):
            raise TypeError(
                'certificates must be asn1crypto.x509.Certificate objects'
            )
        by_der[cert.dump()] = cert
    return dict(sorted(by_der.items(), key=lambda item: item[0]))


def _names_match(child, issuer):
    """
    Checks if the child's issuer name equals the candidate's subject name.
    """

    return child.issuer == issuer.subject


def _key_identifiers_match(child, issuer):
    """
    Matches the child's authorityKeyIdentifier key_identifier against the
    candidate issuer's subjectKeyIdentifier. If the child has no AKI
    key_identifier, any issuer passes. If it does, the issuer must carry a
    matching SKI - this keeps same-name issuers with different keys apart.
    """

    aki = child.authority_key_identifier
    if aki is None:
        return True
    return issuer.key_identifier == aki


def _is_valid_at(certificate, moment):
    """
    Checks the certificate validity period at the fixed moment.
    """

    return certificate.not_valid_before <= moment <= certificate.not_valid_after


def _is_proper_issuer(issuer, chain):
    """
    Checks CA/basic constraints and key usage for a candidate issuer, and
    enforces pathLenConstraint against the non-self-issued CA certificates
    already in the chain below it.
    """

    if not issuer.ca:
        return False

    key_usage = issuer.key_usage_value
    if key_usage is not None and 'key_cert_sign' not in key_usage.native:
        return False

    max_path_length = issuer.max_path_length
    if max_path_length is not None:
        below = sum(
            1 for cert in chain[1:]
            if cert.ca and not cert.self_issued
        )
        if below > max_path_length:
            return False

    return True
