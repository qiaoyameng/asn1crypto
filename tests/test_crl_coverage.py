# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
from datetime import datetime

from asn1crypto import crl, crl_coverage, keys, x509
from asn1crypto.util import timezone

from ._unittest_compat import patch

patch()


def _dt(year, month, day):
    return datetime(year, month, day, tzinfo=timezone.utc)


MOMENT = _dt(2026, 1, 20)

CA_NAME = x509.Name.build({'common_name': 'Test CA'})
OTHER_CA_NAME = x509.Name.build({'common_name': 'Other CA'})
CRL_ISSUER_NAME = x509.Name.build({'common_name': 'CRL Signer'})

DP_URL = 'http://example.com/ca.crl'

REASONS_A = set(['key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded'])
REASONS_B = set(['cessation_of_operation', 'certificate_hold', 'privilege_withdrawn', 'aa_compromise'])


def _dp_name(url=DP_URL):
    return x509.DistributionPointName(
        name='full_name',
        value=x509.GeneralNames([
            x509.GeneralName(name='uniform_resource_identifier', value=url)
        ])
    )


def _make_cert(serial=1000, issuer=CA_NAME, ca=False, with_dp=True, dp_crl_issuer=None):
    extensions = []
    if ca:
        extensions.append(x509.Extension({
            'extn_id': 'basic_constraints',
            'critical': True,
            'extn_value': x509.BasicConstraints({'ca': True}),
        }))
    if with_dp:
        dp_fields = {'distribution_point': _dp_name()}
        if dp_crl_issuer is not None:
            dp_fields['crl_issuer'] = x509.GeneralNames([
                x509.GeneralName(name='directory_name', value=dp_crl_issuer)
            ])
        extensions.append(x509.Extension({
            'extn_id': 'crl_distribution_points',
            'extn_value': x509.CRLDistributionPoints([
                x509.DistributionPoint(dp_fields)
            ]),
        }))
    return x509.Certificate({
        'tbs_certificate': {
            'version': 'v3',
            'serial_number': serial,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': issuer,
            'validity': {
                'not_before': x509.Time(name='utc_time', value=_dt(2025, 1, 1)),
                'not_after': x509.Time(name='utc_time', value=_dt(2027, 1, 1)),
            },
            'subject': x509.Name.build({'common_name': 'End Entity'}),
            'subject_public_key_info': keys.PublicKeyInfo({
                'algorithm': {'algorithm': 'rsa'},
                'public_key': keys.RSAPublicKey({
                    'modulus': 12345678901234567890,
                    'public_exponent': 65537,
                }),
            }),
            'extensions': extensions,
        },
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': b'\x01' * 32,
    })


def _make_crl(issuer=CA_NAME, reasons=None, revoked=(), with_idp=True,
              this_update=_dt(2026, 1, 1), next_update=_dt(2026, 2, 1),
              indirect=False, user_only=False, ca_only=False, dp_url=DP_URL):
    revoked_certificates = []
    for serial, reason, entry_issuer in revoked:
        entry = {
            'user_certificate': serial,
            'revocation_date': x509.Time(name='utc_time', value=_dt(2026, 1, 15)),
        }
        entry_extensions = []
        if reason is not None:
            entry_extensions.append({'extn_id': 'crl_reason', 'extn_value': reason})
        if entry_issuer is not None:
            entry_extensions.append({
                'extn_id': 'certificate_issuer',
                'extn_value': x509.GeneralNames([
                    x509.GeneralName(name='directory_name', value=entry_issuer)
                ]),
            })
        if entry_extensions:
            entry['crl_entry_extensions'] = entry_extensions
        revoked_certificates.append(entry)

    crl_extensions = []
    if with_idp:
        idp_fields = {'distribution_point': _dp_name(dp_url)}
        if reasons is not None:
            idp_fields['only_some_reasons'] = reasons
        if indirect:
            idp_fields['indirect_crl'] = True
        if user_only:
            idp_fields['only_contains_user_certs'] = True
        if ca_only:
            idp_fields['only_contains_ca_certs'] = True
        crl_extensions.append(crl.TBSCertListExtension({
            'extn_id': 'issuing_distribution_point',
            'critical': True,
            'extn_value': crl.IssuingDistributionPoint(idp_fields),
        }))

    tbs = {
        'version': 'v2',
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer,
        'this_update': x509.Time(name='utc_time', value=this_update),
        'next_update': x509.Time(name='utc_time', value=next_update),
        'revoked_certificates': revoked_certificates,
        'crl_extensions': crl_extensions,
    }

    return crl.CertificateList({
        'tbs_cert_list': tbs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x02' * 32,
    })


class CRLCoverageTests(unittest.TestCase):

    def test_missing_one_reason_partition_is_unknown(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)

        result = crl_coverage.evaluate_revocation(cert, [crl_a], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertEqual(REASONS_A, set(result.covered_reasons))
        self.assertEqual(REASONS_B, set(result.missing_reasons))
        self.assertIsNone(result.revocation_date)

    def test_two_complementary_crls_complete_coverage_is_good(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b = _make_crl(reasons=REASONS_B)

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b], MOMENT)

        self.assertEqual('good', result.status)
        self.assertEqual(crl_coverage.ALL_REASONS, result.covered_reasons)
        self.assertEqual(frozenset(), result.missing_reasons)
        self.assertEqual(2, len(result.assessments))
        for assessment in result.assessments:
            self.assertTrue(assessment.applicable)
            self.assertEqual((), assessment.problems)

    def test_explicitly_revoked_certificate(self):
        cert = _make_cert(serial=1000)
        crl_a = _make_crl(reasons=REASONS_A, revoked=[(1000, 'key_compromise', None)])
        crl_b = _make_crl(reasons=REASONS_B)

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b], MOMENT)

        self.assertEqual('revoked', result.status)
        self.assertEqual('key_compromise', result.revocation_reason)
        self.assertEqual(_dt(2026, 1, 15), result.revocation_date)
        self.assertEqual(CA_NAME, result.revoking_crl_issuer)

    def test_expired_crl_provides_no_coverage(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b_expired = _make_crl(reasons=REASONS_B, next_update=_dt(2026, 1, 10))

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b_expired], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertEqual(REASONS_B, set(result.missing_reasons))
        self.assertFalse(result.assessments[1].applicable)
        self.assertIn('expired', result.assessments[1].problems)

    def test_not_yet_valid_crl_provides_no_coverage(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b_future = _make_crl(reasons=REASONS_B, this_update=_dt(2026, 2, 1))

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b_future], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertIn('not_yet_valid', result.assessments[1].problems)

    def test_issuer_mismatch_provides_no_coverage(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b_wrong_issuer = _make_crl(issuer=OTHER_CA_NAME, reasons=REASONS_B)

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b_wrong_issuer], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertEqual(REASONS_B, set(result.missing_reasons))
        self.assertFalse(result.assessments[1].applicable)
        self.assertIn('issuer_mismatch', result.assessments[1].problems)

    def test_distribution_point_mismatch_provides_no_coverage(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b_other_dp = _make_crl(reasons=REASONS_B, dp_url='http://example.com/other.crl')

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b_other_dp], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertIn('distribution_point_mismatch', result.assessments[1].problems)

    def test_user_only_crl_does_not_cover_ca_cert(self):
        cert = _make_cert(ca=True)
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b_users_only = _make_crl(reasons=REASONS_B, user_only=True)

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b_users_only], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertIn('only_contains_user_certs', result.assessments[1].problems)

    def test_ca_only_crl_does_not_cover_end_entity_cert(self):
        cert = _make_cert()
        crl_a = _make_crl(reasons=REASONS_A)
        crl_b_ca_only = _make_crl(reasons=REASONS_B, ca_only=True)

        result = crl_coverage.evaluate_revocation(cert, [crl_a, crl_b_ca_only], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertIn('only_contains_ca_certs', result.assessments[1].problems)

    def test_indirect_crl_issuer_from_distribution_point(self):
        cert = _make_cert(dp_crl_issuer=CRL_ISSUER_NAME)
        indirect_crl = _make_crl(
            issuer=CRL_ISSUER_NAME,
            reasons=None,
            indirect=True,
            revoked=[(1000, 'affiliation_changed', CA_NAME)],
        )

        result = crl_coverage.evaluate_revocation(cert, [indirect_crl], MOMENT)

        self.assertEqual('revoked', result.status)
        self.assertEqual('affiliation_changed', result.revocation_reason)
        self.assertEqual(CRL_ISSUER_NAME, result.revoking_crl_issuer)

    def test_indirect_crl_ignores_entries_for_other_issuers(self):
        cert = _make_cert(dp_crl_issuer=CRL_ISSUER_NAME)
        indirect_crl = _make_crl(
            issuer=CRL_ISSUER_NAME,
            reasons=None,
            indirect=True,
            revoked=[(1000, 'key_compromise', OTHER_CA_NAME)],
        )

        result = crl_coverage.evaluate_revocation(cert, [indirect_crl], MOMENT)

        self.assertEqual('good', result.status)
        self.assertIsNone(result.revocation_date)

    def test_indirect_crl_without_crl_issuer_name_is_unusable(self):
        cert = _make_cert()
        indirect_crl = _make_crl(issuer=CRL_ISSUER_NAME, reasons=None, indirect=True)

        result = crl_coverage.evaluate_revocation(cert, [indirect_crl], MOMENT)

        self.assertEqual('unknown', result.status)
        self.assertIn('indirect_crl_issuer_unknown', result.assessments[0].problems)

    def test_crl_without_idp_covers_all_reasons(self):
        cert = _make_cert()
        complete_crl = _make_crl(with_idp=False)

        result = crl_coverage.evaluate_revocation(cert, [complete_crl], MOMENT)

        self.assertEqual('good', result.status)
        self.assertEqual(crl_coverage.ALL_REASONS, result.covered_reasons)

    def test_naive_moment_is_rejected(self):
        cert = _make_cert()
        with self.assertRaises(ValueError):
            crl_coverage.evaluate_revocation(cert, [], datetime(2026, 1, 20))

    def test_wrong_input_types_are_rejected(self):
        cert = _make_cert()
        with self.assertRaises(TypeError):
            crl_coverage.evaluate_revocation('not a cert', [], MOMENT)
        with self.assertRaises(TypeError):
            crl_coverage.evaluate_revocation(cert, ['not a crl'], MOMENT)
