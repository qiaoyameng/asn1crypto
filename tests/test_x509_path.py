# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest

from asn1crypto import core, keys, x509, x509_path
from asn1crypto.util import timezone


VERIFICATION_TIME = datetime(2025, 6, 1, tzinfo=timezone.utc)


def _extension(extn_id, value, critical=False):
    return x509.Extension({
        'extn_id': extn_id,
        'critical': critical,
        'extn_value': core.ParsableOctetString(parsed=value),
    })


def _cert(serial, subject_cn, issuer_cn, ski, aki=None, ca=False,
          path_len=None, not_before=None, not_after=None, signer_ski=None):
    if not_before is None:
        not_before = datetime(2024, 1, 1, tzinfo=timezone.utc)
    if not_after is None:
        not_after = datetime(2026, 1, 1, tzinfo=timezone.utc)

    extensions = [
        _extension('key_identifier', x509.OctetString(ski.encode('ascii'))),
    ]
    if aki is not None:
        extensions.append(_extension(
            'authority_key_identifier',
            x509.AuthorityKeyIdentifier({'key_identifier': aki.encode('ascii')})
        ))
    if ca:
        basic_constraints_kwargs = {'ca': True}
        if path_len is not None:
            basic_constraints_kwargs['path_len_constraint'] = path_len
        extensions.append(_extension(
            'basic_constraints',
            x509.BasicConstraints(basic_constraints_kwargs),
            True
        ))
        extensions.append(_extension(
            'key_usage',
            x509.KeyUsage({'key_cert_sign'}),
            True
        ))

    public_key = keys.RSAPublicKey({
        'modulus': 100000 + serial,
        'public_exponent': 65537,
    })
    signer_ski = signer_ski or ski

    return x509.Certificate({
        'tbs_certificate': {
            'version': 'v3',
            'serial_number': serial,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': x509.Name.build({'common_name': issuer_cn}),
            'validity': {
                'not_before': {'utc_time': not_before},
                'not_after': {'utc_time': not_after},
            },
            'subject': x509.Name.build({'common_name': subject_cn}),
            'subject_public_key_info': keys.PublicKeyInfo.wrap(
                public_key.dump(), 'rsa'
            ),
            'extensions': extensions,
        },
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': b'signed-by:' + signer_ski.encode('ascii'),
    })


def _verify_signature(child_certificate, issuer_certificate):
    return child_certificate.signature == (
        b'signed-by:' + issuer_certificate.key_identifier
    )


def _common_name(certificate):
    return certificate.subject.chosen[0][0]['value'].native


class X509PathTests(unittest.TestCase):

    def test_expired_cross_path_and_valid_path_to_anchor(self):
        valid_anchor = _cert(
            1, 'Valid Anchor', 'Valid Anchor', 'valid-anchor',
            ca=True, path_len=2,
            not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        expired_anchor = _cert(
            2, 'Expired Anchor', 'Expired Anchor', 'expired-anchor',
            ca=True,
            not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        valid_intermediate = _cert(
            3, 'Shared Intermediate', 'Valid Anchor',
            'intermediate-valid', 'valid-anchor', ca=True, path_len=0,
            signer_ski='valid-anchor',
        )
        expired_intermediate = _cert(
            4, 'Shared Intermediate', 'Expired Anchor',
            'intermediate-expired', 'expired-anchor', ca=True, path_len=0,
            not_after=datetime(2024, 6, 1, tzinfo=timezone.utc),
            signer_ski='expired-anchor',
        )
        leaf = _cert(
            5, 'Leaf', 'Shared Intermediate', 'leaf',
            signer_ski='intermediate-valid',
        )

        candidates = [valid_intermediate, expired_intermediate]
        anchors = [valid_anchor, expired_anchor]
        result = x509_path.build_candidate_paths(
            leaf, candidates, anchors, VERIFICATION_TIME, _verify_signature
        )
        reversed_result = x509_path.build_candidate_paths(
            leaf, list(reversed(candidates)), list(reversed(anchors)),
            VERIFICATION_TIME, _verify_signature
        )

        self.assertEqual(1, len(result.paths))
        self.assertFalse(result.incomplete)
        self.assertEqual(
            ('Leaf', 'Shared Intermediate', 'Valid Anchor'),
            tuple(_common_name(certificate) for certificate in result.paths[0])
        )
        self.assertEqual(result.paths, reversed_result.paths)

    def test_cross_signed_intermediate_paths_are_ordered_deterministically(self):
        anchor_a = _cert(1, 'Anchor A', 'Anchor A', 'anchor-a', ca=True)
        anchor_b = _cert(2, 'Anchor B', 'Anchor B', 'anchor-b', ca=True)
        intermediate_a = _cert(
            3, 'Shared Intermediate', 'Anchor A',
            'intermediate-shared', 'anchor-a', ca=True, path_len=0,
            signer_ski='anchor-a',
        )
        intermediate_b = _cert(
            4, 'Shared Intermediate', 'Anchor B',
            'intermediate-shared', 'anchor-b', ca=True, path_len=0,
            signer_ski='anchor-b',
        )
        leaf = _cert(
            5, 'Leaf', 'Shared Intermediate', 'leaf',
            signer_ski='intermediate-shared',
        )

        result = x509_path.build_candidate_paths(
            leaf, [intermediate_a, intermediate_b], [anchor_a, anchor_b],
            VERIFICATION_TIME, _verify_signature
        )
        reversed_result = x509_path.build_candidate_paths(
            leaf, [intermediate_b, intermediate_a], [anchor_b, anchor_a],
            VERIFICATION_TIME, _verify_signature
        )

        self.assertEqual(2, len(result.paths))
        self.assertFalse(result.incomplete)
        self.assertEqual(result.paths, reversed_result.paths)
        expected_first_intermediate = sorted(
            [intermediate_a, intermediate_b],
            key=lambda certificate: certificate.sha256
        )[0]
        self.assertIs(expected_first_intermediate, result.paths[0][1])

    def test_failed_signature_edge_is_not_used(self):
        anchor = _cert(1, 'Anchor', 'Anchor', 'anchor', ca=True)
        valid_intermediate = _cert(
            2, 'Shared Intermediate', 'Anchor', 'intermediate-valid',
            'anchor', ca=True, signer_ski='anchor',
        )
        rogue_intermediate = _cert(
            3, 'Shared Intermediate', 'Anchor', 'intermediate-rogue',
            'anchor', ca=True,
        )
        leaf = _cert(
            4, 'Leaf', 'Shared Intermediate', 'leaf',
            signer_ski='intermediate-valid',
        )

        result = x509_path.build_candidate_paths(
            leaf, [rogue_intermediate, valid_intermediate], [anchor],
            VERIFICATION_TIME, _verify_signature
        )

        self.assertEqual(1, len(result.paths))
        self.assertIs(valid_intermediate, result.paths[0][1])

    def test_mismatched_authority_and_subject_key_identifiers_reject_edge(self):
        anchor = _cert(1, 'Anchor', 'Anchor', 'anchor', ca=True)
        mismatched_intermediate = _cert(
            2, 'Shared Intermediate', 'Anchor', 'intermediate-other',
            'anchor', ca=True, signer_ski='anchor',
        )
        leaf = _cert(
            3, 'Leaf', 'Shared Intermediate', 'leaf', 'intermediate-valid',
            signer_ski='intermediate-other',
        )

        def callback_should_not_be_used(child_certificate, issuer_certificate):
            raise AssertionError('structural edge should not reach signature verification')

        result = x509_path.build_candidate_paths(
            leaf, [mismatched_intermediate], [anchor], VERIFICATION_TIME,
            callback_should_not_be_used
        )

        self.assertEqual((), result.paths)

    def test_self_issued_intermediate_is_allowed_without_creating_a_loop(self):
        anchor = _cert(
            1, 'Shared CA', 'Shared CA', 'ca-current', ca=True, path_len=1,
        )
        self_issued = _cert(
            2, 'Shared CA', 'Shared CA', 'ca-previous', 'ca-current',
            ca=True, signer_ski='ca-current',
        )
        loop = _cert(
            3, 'Shared CA', 'Shared CA', 'ca-loop', ca=True,
            signer_ski='ca-loop',
        )
        intermediate = _cert(
            4, 'Issuing CA', 'Shared CA', 'issuing-ca', 'ca-previous',
            ca=True, path_len=0, signer_ski='ca-previous',
        )
        leaf = _cert(
            5, 'Leaf', 'Issuing CA', 'leaf', 'issuing-ca',
            signer_ski='issuing-ca',
        )

        result = x509_path.build_candidate_paths(
            leaf, [loop, self_issued, intermediate], [anchor],
            VERIFICATION_TIME, _verify_signature
        )

        self.assertEqual(1, len(result.paths))
        self.assertEqual(
            (leaf, intermediate, self_issued, anchor),
            result.paths[0]
        )

    def test_path_length_constraint_is_enforced(self):
        anchor = _cert(
            1, 'Anchor', 'Anchor', 'anchor', ca=True, path_len=0,
        )
        intermediate = _cert(
            2, 'Intermediate', 'Anchor', 'intermediate', 'anchor',
            ca=True, path_len=0, signer_ski='anchor',
        )
        leaf = _cert(
            3, 'Leaf', 'Intermediate', 'leaf', 'intermediate',
            signer_ski='intermediate',
        )

        result = x509_path.build_candidate_paths(
            leaf, [intermediate], [anchor], VERIFICATION_TIME, _verify_signature
        )

        self.assertEqual((), result.paths)
        self.assertFalse(result.incomplete)

    def test_search_limit_reports_unexhausted_space(self):
        anchor_a = _cert(1, 'Anchor A', 'Anchor A', 'anchor-a', ca=True)
        anchor_b = _cert(2, 'Anchor B', 'Anchor B', 'anchor-b', ca=True)
        intermediate_a = _cert(
            3, 'Shared Intermediate', 'Anchor A', 'intermediate-shared',
            'anchor-a', ca=True, path_len=0, signer_ski='anchor-a',
        )
        intermediate_b = _cert(
            4, 'Shared Intermediate', 'Anchor B', 'intermediate-shared',
            'anchor-b', ca=True, path_len=0, signer_ski='anchor-b',
        )
        leaf = _cert(
            5, 'Leaf', 'Shared Intermediate', 'leaf', 'intermediate-shared',
            signer_ski='intermediate-shared',
        )

        limited = x509_path.build_candidate_paths(
            leaf, [intermediate_a, intermediate_b], [anchor_a, anchor_b],
            VERIFICATION_TIME, _verify_signature, max_paths=1
        )
        complete = x509_path.build_candidate_paths(
            leaf, [intermediate_a, intermediate_b], [anchor_a, anchor_b],
            VERIFICATION_TIME, _verify_signature
        )

        self.assertEqual(1, len(limited.paths))
        self.assertTrue(limited.incomplete)
        self.assertEqual(2, len(complete.paths))
        self.assertFalse(complete.incomplete)

    def test_limitations_are_documented(self):
        self.assertTrue(any('revocation' in item for item in x509_path.LIMITATIONS))
        self.assertTrue(any(
            'unrecognized critical extensions' in item
            for item in x509_path.LIMITATIONS
        ))

    def test_verification_time_must_be_timezone_aware(self):
        anchor = _cert(1, 'Anchor', 'Anchor', 'anchor', ca=True)
        leaf = _cert(2, 'Leaf', 'Anchor', 'leaf')

        with self.assertRaises(ValueError):
            x509_path.build_candidate_paths(
                leaf, [], [anchor], datetime(2025, 6, 1), _verify_signature
            )


if __name__ == '__main__':
    unittest.main()
