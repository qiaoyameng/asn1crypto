# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
from datetime import datetime

from asn1crypto import crl, keys, x509
from asn1crypto.crl_check import (
    ALL_REVOCATION_REASONS,
    assess_crl_coverage,
)
from asn1crypto.util import timezone

from ._unittest_compat import patch

patch()


def _time(year, month, day):
    return x509.Time(
        name='utc_time',
        value=datetime(year, month, day, tzinfo=timezone.utc)
    )


CA_NAME = x509.Name.build({
    'country_name': 'US',
    'organization_name': 'Test CA Org',
    'common_name': 'Test CA',
})

OTHER_CA_NAME = x509.Name.build({
    'country_name': 'US',
    'organization_name': 'Other CA Org',
    'common_name': 'Other CA',
})

REASONS_A = set(['key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded'])
REASONS_B = set(['cessation_of_operation', 'certificate_hold', 'privilege_withdrawn',
                 'aa_compromise', 'unused'])

MOMENT = datetime(2026, 1, 20, tzinfo=timezone.utc)


def _build_certificate(serial_number=1000, issuer_name=CA_NAME, is_ca=False,
                       crl_distribution_points=None):
    extensions = [
        {'extn_id': 'basic_constraints', 'extn_value': {'ca': is_ca}},
    ]
    if crl_distribution_points is not None:
        extensions.append({
            'extn_id': 'crl_distribution_points',
            'extn_value': crl_distribution_points,
        })
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial_number,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer_name,
        'validity': {
            'not_before': _time(2026, 1, 1),
            'not_after': _time(2027, 1, 1),
        },
        'subject': x509.Name.build({'common_name': 'End Entity'}),
        'subject_public_key_info': {
            'algorithm': {'algorithm': 'rsa'},
            'public_key': keys.RSAPublicKey({
                'modulus': 12345678901234567890,
                'public_exponent': 65537,
            }),
        },
        'extensions': extensions,
    })
    return x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': b'\x00' * 16,
    })


def _build_crl(issuer_name=CA_NAME, only_some_reasons=None, revoked=None,
               indirect_crl=False, only_contains_user_certs=False,
               only_contains_ca_certs=False, next_update=(2026, 2, 1),
               issuing_distribution_point=True):
    revoked_certificates = []
    for serial_number, reason, certificate_issuer in (revoked or []):
        entry_extensions = []
        if reason is not None:
            entry_extensions.append({'extn_id': 'crl_reason', 'extn_value': reason})
        if certificate_issuer is not None:
            entry_extensions.append({
                'extn_id': 'certificate_issuer',
                'extn_value': x509.GeneralNames([
                    x509.GeneralName(name='directory_name', value=certificate_issuer),
                ]),
            })
        entry = {
            'user_certificate': serial_number,
            'revocation_date': _time(2026, 1, 15),
        }
        if entry_extensions:
            entry['crl_entry_extensions'] = entry_extensions
        revoked_certificates.append(entry)

    crl_extensions = []
    if issuing_distribution_point:
        idp = crl.IssuingDistributionPoint({
            'only_contains_user_certs': only_contains_user_certs,
            'only_contains_ca_certs': only_contains_ca_certs,
            'indirect_crl': indirect_crl,
        })
        if only_some_reasons is not None:
            idp['only_some_reasons'] = x509.ReasonFlags(set(only_some_reasons))
        crl_extensions.append({
            'extn_id': 'issuing_distribution_point',
            'extn_value': idp,
        })

    tbs = crl.TbsCertList({
        'version': 'v2',
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer_name,
        'this_update': _time(2026, 1, 1),
        'revoked_certificates': revoked_certificates,
        'crl_extensions': crl_extensions,
    })
    if next_update is not None:
        tbs['next_update'] = _time(*next_update)

    return crl.CertificateList({
        'tbs_cert_list': tbs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x00' * 16,
    })


def _partial_crls():
    crl_a = _build_crl(only_some_reasons=REASONS_A)
    crl_b = _build_crl(only_some_reasons=REASONS_B)
    return crl_a, crl_b


class CRLCheckTests(unittest.TestCase):

    def test_missing_partial_crl_is_unknown(self):
        cert = _build_certificate()
        crl_a, _ = _partial_crls()

        assessment = assess_crl_coverage(cert, [crl_a], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.covered_reasons)
        self.assertEqual(REASONS_B, assessment.missing_reasons)
        self.assertEqual((crl_a,), assessment.applicable_crls)

    def test_combined_partial_crls_is_good(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()

        assessment = assess_crl_coverage(cert, [crl_a, crl_b], MOMENT)

        self.assertEqual('good', assessment.status)
        self.assertEqual(ALL_REVOCATION_REASONS, assessment.covered_reasons)
        self.assertEqual(set(), assessment.missing_reasons)
        self.assertEqual((crl_a, crl_b), assessment.applicable_crls)

    def test_explicitly_revoked(self):
        cert = _build_certificate()
        crl_a = _build_crl(
            only_some_reasons=REASONS_A,
            revoked=[(1000, 'key_compromise', None)],
        )

        assessment = assess_crl_coverage(cert, [crl_a], MOMENT)

        self.assertEqual('revoked', assessment.status)
        self.assertEqual('key_compromise', assessment.revocation_reason)
        self.assertEqual(
            datetime(2026, 1, 15, tzinfo=timezone.utc),
            assessment.revocation_date
        )
        self.assertEqual(crl_a, assessment.revoking_crl)

    def test_revoked_entry_for_other_serial_is_good(self):
        cert = _build_certificate(serial_number=1000)
        crl_a, crl_b = _partial_crls()
        crl_a['tbs_cert_list']['revoked_certificates'] = [
            {
                'user_certificate': 2000,
                'revocation_date': _time(2026, 1, 15),
                'crl_entry_extensions': [
                    {'extn_id': 'crl_reason', 'extn_value': 'key_compromise'},
                ],
            },
        ]

        assessment = assess_crl_coverage(cert, [crl_a, crl_b], MOMENT)

        self.assertEqual('good', assessment.status)

    def test_expired_crl_provides_no_coverage(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()
        expired_crl_a = _build_crl(only_some_reasons=REASONS_A, next_update=(2026, 1, 10))

        assessment = assess_crl_coverage(cert, [expired_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)
        self.assertEqual((crl_b,), assessment.applicable_crls)

    def test_not_yet_valid_crl_provides_no_coverage(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()
        future_crl_a = _build_crl(only_some_reasons=REASONS_A)
        future_crl_a['tbs_cert_list']['this_update'] = _time(2026, 2, 1)

        assessment = assess_crl_coverage(cert, [future_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)

    def test_issuer_name_mismatch_provides_no_coverage(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()
        mismatched_crl_a = _build_crl(issuer_name=OTHER_CA_NAME, only_some_reasons=REASONS_A)

        assessment = assess_crl_coverage(cert, [mismatched_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)

    def test_only_contains_ca_certs_excludes_end_entity_cert(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()
        ca_only_crl_a = _build_crl(
            only_some_reasons=REASONS_A,
            only_contains_ca_certs=True,
        )

        assessment = assess_crl_coverage(cert, [ca_only_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)

    def test_only_contains_user_certs_excludes_ca_cert(self):
        cert = _build_certificate(is_ca=True)
        _, crl_b = _partial_crls()
        user_only_crl_a = _build_crl(
            only_some_reasons=REASONS_A,
            only_contains_user_certs=True,
        )

        assessment = assess_crl_coverage(cert, [user_only_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)

    def test_crl_without_idp_covers_all_reasons(self):
        cert = _build_certificate()
        complete_crl = _build_crl(issuing_distribution_point=False)

        assessment = assess_crl_coverage(cert, [complete_crl], MOMENT)

        self.assertEqual('good', assessment.status)
        self.assertEqual(ALL_REVOCATION_REASONS, assessment.covered_reasons)

    def test_indirect_crl_revocation_with_certificate_issuer(self):
        cert = _build_certificate()
        _, crl_b = _partial_crls()
        indirect_crl_a = _build_crl(
            issuer_name=OTHER_CA_NAME,
            only_some_reasons=REASONS_A,
            indirect_crl=True,
            revoked=[(1000, 'cessation_of_operation', CA_NAME)],
        )

        assessment = assess_crl_coverage(cert, [indirect_crl_a, crl_b], MOMENT)

        self.assertEqual('revoked', assessment.status)
        self.assertEqual('cessation_of_operation', assessment.revocation_reason)

    def test_indirect_crl_entry_for_other_issuer_does_not_match(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()
        indirect_crl_a = _build_crl(
            issuer_name=OTHER_CA_NAME,
            only_some_reasons=REASONS_A,
            indirect_crl=True,
            revoked=[(1000, 'key_compromise', OTHER_CA_NAME)],
        )

        assessment = assess_crl_coverage(cert, [indirect_crl_a, crl_b], MOMENT)

        self.assertEqual('good', assessment.status)

    def test_indirect_crl_provides_coverage_despite_issuer_mismatch(self):
        cert = _build_certificate()
        _, crl_b = _partial_crls()
        indirect_crl_a = _build_crl(
            issuer_name=OTHER_CA_NAME,
            only_some_reasons=REASONS_A,
            indirect_crl=True,
        )

        assessment = assess_crl_coverage(cert, [indirect_crl_a, crl_b], MOMENT)

        self.assertEqual('good', assessment.status)

    def test_distribution_point_reasons_limit_required_coverage(self):
        distribution_points = x509.CRLDistributionPoints([
            {
                'distribution_point': x509.DistributionPointName(
                    name='full_name',
                    value=x509.GeneralNames([
                        x509.GeneralName(
                            name='uniform_resource_identifier',
                            value='http://example.com/ca.crl'
                        ),
                    ])
                ),
                'reasons': x509.ReasonFlags(set(REASONS_A)),
            },
        ])
        cert = _build_certificate(crl_distribution_points=distribution_points)
        crl_a, _ = _partial_crls()

        assessment = assess_crl_coverage(cert, [crl_a], MOMENT)

        self.assertEqual('good', assessment.status)
        self.assertEqual(REASONS_A, assessment.covered_reasons)

    def test_idp_distribution_point_name_must_match_certificate(self):
        distribution_points = x509.CRLDistributionPoints([
            {
                'distribution_point': x509.DistributionPointName(
                    name='full_name',
                    value=x509.GeneralNames([
                        x509.GeneralName(
                            name='uniform_resource_identifier',
                            value='http://example.com/ca.crl'
                        ),
                    ])
                ),
            },
        ])
        cert = _build_certificate(crl_distribution_points=distribution_points)
        _, crl_b = _partial_crls()

        idp = crl.IssuingDistributionPoint({
            'distribution_point': x509.DistributionPointName(
                name='full_name',
                value=x509.GeneralNames([
                    x509.GeneralName(
                        name='uniform_resource_identifier',
                        value='http://other.example.com/ca.crl'
                    ),
                ])
            ),
            'only_some_reasons': x509.ReasonFlags(set(REASONS_A)),
        })
        mismatched_crl_a = _build_crl()
        mismatched_crl_a['tbs_cert_list']['crl_extensions'] = [
            {'extn_id': 'issuing_distribution_point', 'extn_value': idp},
        ]

        assessment = assess_crl_coverage(cert, [mismatched_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)

    def test_delta_crl_provides_no_coverage(self):
        cert = _build_certificate()
        _, crl_b = _partial_crls()
        delta_crl_a = _build_crl(only_some_reasons=REASONS_A)
        delta_crl_a['tbs_cert_list']['crl_extensions'] = [
            {
                'extn_id': 'issuing_distribution_point',
                'extn_value': crl.IssuingDistributionPoint({
                    'only_some_reasons': x509.ReasonFlags(set(REASONS_A)),
                }),
            },
            {'extn_id': 'delta_crl_indicator', 'extn_value': 42},
        ]

        assessment = assess_crl_coverage(cert, [delta_crl_a, crl_b], MOMENT)

        self.assertEqual('unknown', assessment.status)
        self.assertEqual(REASONS_A, assessment.missing_reasons)

    def test_naive_moment_is_treated_as_utc(self):
        cert = _build_certificate()
        crl_a, crl_b = _partial_crls()

        assessment = assess_crl_coverage(
            cert,
            [crl_a, crl_b],
            datetime(2026, 1, 20)
        )

        self.assertEqual('good', assessment.status)
