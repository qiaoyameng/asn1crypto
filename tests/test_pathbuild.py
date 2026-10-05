# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import itertools
import unittest
from datetime import datetime

from asn1crypto import keys, pathbuild, util, x509

from ._unittest_compat import patch

patch()


MOMENT = datetime(2025, 6, 1, tzinfo=util.timezone.utc)
VALID_FROM = datetime(2020, 1, 1, tzinfo=util.timezone.utc)
VALID_TO = datetime(2030, 1, 1, tzinfo=util.timezone.utc)
EXPIRED_TO = datetime(2021, 1, 1, tzinfo=util.timezone.utc)


def _name(common_name):
    return x509.Name.build({
        'common_name': common_name,
        'organization_name': 'Path Builder Demo',
    })


def _make_cert(serial, subject_cn, issuer_cn, ski=None, aki=None, ca=False,
               path_len=None, key_usages=None, not_before=VALID_FROM,
               not_after=VALID_TO):
    extensions = []
    if ca or path_len is not None:
        basic_constraints = {'ca': ca}
        if path_len is not None:
            basic_constraints['path_len_constraint'] = path_len
        extensions.append({
            'extn_id': 'basic_constraints',
            'critical': True,
            'extn_value': basic_constraints,
        })
    if key_usages is not None:
        extensions.append({
            'extn_id': 'key_usage',
            'critical': True,
            'extn_value': set(key_usages),
        })
    if ski is not None:
        extensions.append({
            'extn_id': 'key_identifier',
            'extn_value': ski,
        })
    if aki is not None:
        extensions.append({
            'extn_id': 'authority_key_identifier',
            'extn_value': {'key_identifier': aki},
        })

    tbs = {
        'version': 'v3',
        'serial_number': serial,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': _name(issuer_cn),
        'validity': {
            'not_before': {'utc_time': not_before},
            'not_after': {'utc_time': not_after},
        },
        'subject': _name(subject_cn),
        'subject_public_key_info': keys.PublicKeyInfo({
            'algorithm': {'algorithm': 'rsa'},
            'public_key': keys.RSAPublicKey({
                'modulus': 2 ** 255 + serial,
                'public_exponent': 65537,
            }),
        }),
    }
    if extensions:
        tbs['extensions'] = extensions

    return x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': b'\x01' * 64,
    })


class _Signer(object):
    """
    A deterministic, pure stand-in for real signature verification. Edges
    are registered with sign(); verify() only consults the registry.
    """

    def __init__(self):
        self._edges = set()

    def sign(self, issuer, subject):
        self._edges.add((issuer.dump(), subject.dump()))

    def verify(self, issuer, subject):
        return (issuer.dump(), subject.dump()) in self._edges


def _path_ders(paths):
    return [tuple(cert.dump() for cert in path) for path in paths]


class PathBuildTests(unittest.TestCase):

    def _main_graph(self):
        """
        Builds a graph where the leaf's issuer name "Intermediate CA" is
        shared by four distinct certificates:

         - inter_ok: valid, properly signed, reaches the root
         - inter_expired: properly signed but expired at the fixed moment
         - inter_badsig: valid CA, but the leaf's signature does not verify
           with its key
         - inter_noku: valid and signed, but its keyUsage lacks keyCertSign
         - inter_self: a dangling self-issued certificate
        """

        signer = _Signer()

        root = _make_cert(
            1, 'Root CA', 'Root CA', ski=b'R', ca=True, path_len=4,
            key_usages=['key_cert_sign'],
        )
        inter_ok = _make_cert(
            2, 'Intermediate CA', 'Root CA', ski=b'I-OK', aki=b'R',
            ca=True, path_len=0, key_usages=['key_cert_sign'],
        )
        inter_expired = _make_cert(
            3, 'Intermediate CA', 'Root CA', ski=b'I-OLD', aki=b'R',
            ca=True, key_usages=['key_cert_sign'], not_after=EXPIRED_TO,
        )
        inter_badsig = _make_cert(
            4, 'Intermediate CA', 'Root CA', ski=b'I-BAD', aki=b'R',
            ca=True, key_usages=['key_cert_sign'],
        )
        inter_noku = _make_cert(
            5, 'Intermediate CA', 'Root CA', ski=b'I-NOKU', aki=b'R',
            ca=True, key_usages=['digital_signature'],
        )
        inter_self = _make_cert(
            6, 'Intermediate CA', 'Intermediate CA', ski=b'I-SELF',
            aki=b'I-SELF', ca=True, key_usages=['key_cert_sign'],
        )
        leaf = _make_cert(7, 'Leaf', 'Intermediate CA')

        signer.sign(root, inter_ok)
        signer.sign(root, inter_expired)
        signer.sign(root, inter_badsig)
        signer.sign(root, inter_noku)
        signer.sign(inter_self, inter_self)
        signer.sign(inter_ok, leaf)
        signer.sign(inter_expired, leaf)
        signer.sign(inter_noku, leaf)
        # Deliberately no edge inter_badsig -> leaf: the deterministic
        # callback rejects it, so that edge must not be used.

        intermediates = [
            inter_ok,
            inter_expired,
            inter_badsig,
            inter_noku,
            inter_self,
            inter_ok,  # exact duplicate, must be deduplicated
            root,      # anchors may also appear among the candidates
        ]
        return signer, leaf, intermediates, [root], inter_ok, root

    def test_single_reachable_path_out_of_expired_and_broken_ones(self):
        signer, leaf, intermediates, anchors, inter_ok, root = self._main_graph()

        result = pathbuild.PathBuilder(signer.verify).build(
            leaf, intermediates, anchors, MOMENT
        )

        self.assertTrue(result.exhausted)
        self.assertEqual(1, len(result.paths))
        self.assertEqual(
            (leaf.dump(), inter_ok.dump(), root.dump()),
            tuple(cert.dump() for cert in result.paths[0]),
        )

    def test_path_order_independent_of_candidate_order(self):
        signer, leaf, intermediates, anchors, _, _ = self._main_graph()
        builder = pathbuild.PathBuilder(signer.verify)

        baseline = _path_ders(
            builder.build(leaf, intermediates, anchors, MOMENT).paths
        )

        distinct = list(dict.fromkeys(intermediates))
        for permuted in itertools.permutations(distinct):
            result = builder.build(leaf, list(permuted), anchors, MOMENT)
            self.assertTrue(result.exhausted)
            self.assertEqual(baseline, _path_ders(result.paths))

        reversed_anchors = builder.build(leaf, intermediates, anchors, MOMENT)
        self.assertEqual(baseline, _path_ders(reversed_anchors.paths))

    def test_self_issued_intermediate_and_aki_ski_disambiguation(self):
        """
        A re-keyed CA: bridge_new is self-issued (same subject and issuer
        name) and certified by bridge_old. The leaf's AKI selects the new
        key, and bridge_new's AKI selects the old one.
        """

        signer = _Signer()

        root = _make_cert(
            11, 'Root CA', 'Root CA', ski=b'R', ca=True, path_len=4,
            key_usages=['key_cert_sign'],
        )
        bridge_old = _make_cert(
            12, 'Bridge CA', 'Root CA', ski=b'B1', aki=b'R',
            ca=True, key_usages=['key_cert_sign'],
        )
        bridge_new = _make_cert(
            13, 'Bridge CA', 'Bridge CA', ski=b'B2', aki=b'B1',
            ca=True, key_usages=['key_cert_sign'],
        )
        leaf = _make_cert(14, 'Leaf 2', 'Bridge CA', aki=b'B2')

        signer.sign(root, bridge_old)
        signer.sign(bridge_old, bridge_new)
        signer.sign(bridge_new, leaf)

        result = pathbuild.PathBuilder(signer.verify).build(
            leaf, [bridge_new, bridge_old], [root], MOMENT
        )

        self.assertTrue(result.exhausted)
        self.assertEqual(1, len(result.paths))
        self.assertEqual(
            (leaf.dump(), bridge_new.dump(), bridge_old.dump(), root.dump()),
            tuple(cert.dump() for cert in result.paths[0]),
        )

    def test_issuer_loops_terminate(self):
        signer = _Signer()

        loop_a = _make_cert(
            21, 'Loop A', 'Loop B', ski=b'LA', aki=b'LB',
            ca=True, key_usages=['key_cert_sign'],
        )
        loop_b = _make_cert(
            22, 'Loop B', 'Loop A', ski=b'LB', aki=b'LA',
            ca=True, key_usages=['key_cert_sign'],
        )
        leaf = _make_cert(23, 'Leaf 3', 'Loop A', aki=b'LA')

        signer.sign(loop_a, loop_b)
        signer.sign(loop_b, loop_a)
        signer.sign(loop_a, leaf)

        result = pathbuild.PathBuilder(signer.verify).build(
            leaf, [loop_a, loop_b], [], MOMENT
        )

        self.assertTrue(result.exhausted)
        self.assertEqual([], result.paths)

    def test_path_len_constraint(self):
        signer = _Signer()

        root = _make_cert(
            31, 'Root CA', 'Root CA', ski=b'R', ca=True, path_len=4,
            key_usages=['key_cert_sign'],
        )
        mid_pl0 = _make_cert(
            32, 'Mid One', 'Root CA', ski=b'M1', aki=b'R',
            ca=True, path_len=0, key_usages=['key_cert_sign'],
        )
        mid_pl1 = _make_cert(
            33, 'Mid One', 'Root CA', ski=b'M1B', aki=b'R',
            ca=True, path_len=1, key_usages=['key_cert_sign'],
        )
        mid_two = _make_cert(
            34, 'Mid Two', 'Mid One', ski=b'M2',
            ca=True, path_len=0, key_usages=['key_cert_sign'],
        )
        leaf = _make_cert(35, 'Leaf 4', 'Mid Two', aki=b'M2')

        signer.sign(root, mid_pl0)
        signer.sign(root, mid_pl1)
        signer.sign(mid_pl0, mid_two)
        signer.sign(mid_pl1, mid_two)
        signer.sign(mid_two, leaf)

        result = pathbuild.PathBuilder(signer.verify).build(
            leaf, [mid_pl0, mid_pl1, mid_two], [root], MOMENT
        )

        # mid_pl0 may not have a non-self-issued CA below it, so only the
        # path through mid_pl1 survives.
        self.assertTrue(result.exhausted)
        self.assertEqual(1, len(result.paths))
        self.assertEqual(
            (leaf.dump(), mid_two.dump(), mid_pl1.dump(), root.dump()),
            tuple(cert.dump() for cert in result.paths[0]),
        )

    def test_search_limits_report_not_exhausted(self):
        signer, leaf, intermediates, anchors, _, _ = self._main_graph()

        by_edges = pathbuild.PathBuilder(signer.verify, max_edge_checks=1)
        self.assertFalse(
            by_edges.build(leaf, intermediates, anchors, MOMENT).exhausted
        )

        by_depth = pathbuild.PathBuilder(signer.verify, max_depth=2)
        self.assertFalse(
            by_depth.build(leaf, intermediates, anchors, MOMENT).exhausted
        )

    def test_max_paths_limit_and_multiple_anchors(self):
        signer = _Signer()

        root_a = _make_cert(
            41, 'Root CA', 'Root CA', ski=b'RA', ca=True,
            key_usages=['key_cert_sign'],
        )
        root_b = _make_cert(
            42, 'Root CA', 'Root CA', ski=b'RB', ca=True,
            key_usages=['key_cert_sign'],
        )
        inter = _make_cert(
            43, 'Inter X', 'Root CA', ski=b'IX', ca=True,
            key_usages=['key_cert_sign'],
        )
        leaf = _make_cert(44, 'Leaf 5', 'Inter X', aki=b'IX')

        signer.sign(root_a, inter)
        signer.sign(root_b, inter)
        signer.sign(inter, leaf)

        full = pathbuild.PathBuilder(signer.verify).build(
            leaf, [inter], [root_a, root_b], MOMENT
        )
        self.assertTrue(full.exhausted)
        self.assertEqual(2, len(full.paths))

        # Both anchor orders must produce the same path order.
        swapped = pathbuild.PathBuilder(signer.verify).build(
            leaf, [inter], [root_b, root_a], MOMENT
        )
        self.assertEqual(_path_ders(full.paths), _path_ders(swapped.paths))

        limited = pathbuild.PathBuilder(signer.verify, max_paths=1).build(
            leaf, [inter], [root_a, root_b], MOMENT
        )
        self.assertFalse(limited.exhausted)
        self.assertEqual(1, len(limited.paths))
        self.assertEqual(_path_ders(full.paths)[:1], _path_ders(limited.paths))

    def test_limitations_are_listed(self):
        self.assertIsInstance(pathbuild.UNIMPLEMENTED_PKIX_FEATURES, tuple)
        self.assertGreater(len(pathbuild.UNIMPLEMENTED_PKIX_FEATURES), 0)
        for feature in pathbuild.UNIMPLEMENTED_PKIX_FEATURES:
            self.assertIsInstance(feature, str)
