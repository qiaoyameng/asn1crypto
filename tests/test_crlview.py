# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime, timedelta
import unittest

from asn1crypto import crl, crlview, x509
from asn1crypto.util import timezone

from ._unittest_compat import patch

patch()


ISSUER_A = x509.Name.build({
    'country_name': 'US',
    'organization_name': 'Test CA',
    'common_name': 'Test CA A',
})

ISSUER_B = x509.Name.build({
    'country_name': 'US',
    'organization_name': 'Test CA',
    'common_name': 'Test CA B',
})

THIS_UPDATE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
NEXT_UPDATE = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
EVALUATION_TIME = datetime(2026, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
REVOCATION_DATE = datetime(2025, 12, 20, 12, 0, 0, tzinfo=timezone.utc)


def _entry(serial, revocation_date=REVOCATION_DATE, reason=None, certificate_issuer=None):
    extensions = []
    if reason is not None:
        extensions.append({'extn_id': 'crl_reason', 'extn_value': reason})
    if certificate_issuer is not None:
        extensions.append({
            'extn_id': 'certificate_issuer',
            'extn_value': x509.GeneralNames([
                x509.GeneralName(name='directory_name', value=certificate_issuer),
            ]),
        })
    entry = {
        'user_certificate': serial,
        'revocation_date': {'general_time': revocation_date},
    }
    if extensions:
        entry['crl_entry_extensions'] = extensions
    return entry


def _make_crl(issuer, crl_number, entries, this_update=THIS_UPDATE, next_update=NEXT_UPDATE,
              delta_indicator=None, aki=None):
    extensions = [
        {'extn_id': 'crl_number', 'extn_value': crl_number},
    ]
    if delta_indicator is not None:
        extensions.append({'extn_id': 'delta_crl_indicator', 'extn_value': delta_indicator})
    if aki is not None:
        extensions.append({
            'extn_id': 'authority_key_identifier',
            'extn_value': {'key_identifier': aki},
        })
    tbs = {
        'version': 'v2',
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer,
        'this_update': {'general_time': this_update},
        'revoked_certificates': entries,
        'crl_extensions': extensions,
    }
    if next_update is not None:
        tbs['next_update'] = {'general_time': next_update}
    return crl.CertificateList({
        'tbs_cert_list': tbs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x01' * 16,
    })


class CRLViewTests(unittest.TestCase):

    def test_compose_single_revocation(self):
        base = _make_crl(ISSUER_A, 5, [_entry(50, reason='key_compromise')])
        delta = _make_crl(ISSUER_A, 6, [_entry(100, reason='key_compromise')], delta_indicator=5)

        view = crlview.compose_crls(base, delta, EVALUATION_TIME)

        self.assertEqual(5, view.base_crl_number)
        self.assertEqual(6, view.delta_crl_number)
        self.assertEqual(2, len(view))

        record = view.get_status(ISSUER_A, 100)
        self.assertIsNotNone(record)
        self.assertEqual('delta', record.source)
        self.assertEqual('key_compromise', record.reason)
        self.assertEqual(REVOCATION_DATE, record.revocation_date)

        base_record = view.get_status(ISSUER_A, 50)
        self.assertEqual('base', base_record.source)

        self.assertTrue(view.is_revoked(ISSUER_A, 100))
        self.assertFalse(view.is_revoked(ISSUER_A, 101))
        self.assertIsNone(view.get_status(ISSUER_A, 101))

    def test_compose_reinstatement(self):
        base = _make_crl(ISSUER_A, 5, [_entry(100, reason='key_compromise')])
        delta = _make_crl(ISSUER_A, 6, [_entry(100, reason='remove_from_crl')], delta_indicator=5)

        view = crlview.compose_crls(base, delta, EVALUATION_TIME)

        self.assertEqual(0, len(view))
        self.assertFalse(view.is_revoked(ISSUER_A, 100))
        self.assertIsNone(view.get_status(ISSUER_A, 100))

    def test_indirect_crl_issuer_switch_same_serial(self):
        base = _make_crl(ISSUER_A, 5, [
            _entry(100, reason='key_compromise'),
            _entry(100, reason='ca_compromise', certificate_issuer=ISSUER_B),
        ])
        delta = _make_crl(ISSUER_A, 6, [
            _entry(100, reason='remove_from_crl', certificate_issuer=ISSUER_B),
        ], delta_indicator=5)

        view = crlview.compose_crls(base, delta, EVALUATION_TIME)

        # The removeFromCRL entry is scoped to issuer B, so issuer A's
        # revocation of the same serial number must survive
        self.assertEqual(1, len(view))
        record = view.get_status(ISSUER_A, 100)
        self.assertIsNotNone(record)
        self.assertEqual('key_compromise', record.reason)
        self.assertEqual('base', record.source)
        self.assertIsNone(view.get_status(ISSUER_B, 100))
        self.assertFalse(view.is_revoked(ISSUER_B, 100))

    def test_delta_updates_reason(self):
        base = _make_crl(ISSUER_A, 5, [_entry(100, reason='key_compromise')])
        delta = _make_crl(ISSUER_A, 6, [_entry(100, reason='cessation_of_operation')], delta_indicator=5)

        view = crlview.compose_crls(base, delta, EVALUATION_TIME)

        record = view.get_status(ISSUER_A, 100)
        self.assertEqual('cessation_of_operation', record.reason)
        self.assertEqual('delta', record.source)

    def test_expired_base_crl(self):
        base = _make_crl(ISSUER_A, 5, [])
        with self.assertRaises(crlview.CRLExpiredError):
            crlview.compose_crls(base, None, NEXT_UPDATE + timedelta(days=1))

    def test_expired_delta_crl(self):
        base = _make_crl(ISSUER_A, 5, [])
        delta = _make_crl(
            ISSUER_A, 6, [],
            next_update=datetime(2026, 1, 10, 0, 0, 0, tzinfo=timezone.utc),
            delta_indicator=5,
        )
        with self.assertRaises(crlview.CRLExpiredError):
            crlview.compose_crls(base, delta, EVALUATION_TIME)

    def test_not_yet_valid_crl(self):
        base = _make_crl(ISSUER_A, 5, [])
        with self.assertRaises(crlview.CRLNotYetValidError):
            crlview.compose_crls(base, None, THIS_UPDATE - timedelta(days=1))

    def test_delta_indicator_newer_than_base(self):
        base = _make_crl(ISSUER_A, 5, [])
        delta = _make_crl(ISSUER_A, 8, [], delta_indicator=7)
        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.compose_crls(base, delta, EVALUATION_TIME)

    def test_delta_number_not_after_base(self):
        base = _make_crl(ISSUER_A, 5, [])
        delta = _make_crl(ISSUER_A, 5, [], delta_indicator=5)
        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.compose_crls(base, delta, EVALUATION_TIME)

    def test_delta_missing_indicator(self):
        base = _make_crl(ISSUER_A, 5, [])
        not_a_delta = _make_crl(ISSUER_A, 6, [])
        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.compose_crls(base, not_a_delta, EVALUATION_TIME)

    def test_base_is_delta_crl(self):
        base = _make_crl(ISSUER_A, 5, [], delta_indicator=4)
        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.compose_crls(base, None, EVALUATION_TIME)

    def test_issuer_mismatch(self):
        base = _make_crl(ISSUER_A, 5, [])
        delta = _make_crl(ISSUER_B, 6, [], delta_indicator=5)
        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.compose_crls(base, delta, EVALUATION_TIME)

    def test_authority_key_identifier_mismatch(self):
        base = _make_crl(ISSUER_A, 5, [], aki=b'\x01' * 20)
        delta = _make_crl(ISSUER_A, 6, [], delta_indicator=5, aki=b'\x02' * 20)
        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.compose_crls(base, delta, EVALUATION_TIME)

    def test_duplicate_conflicting_entries(self):
        base = _make_crl(ISSUER_A, 5, [
            _entry(100, reason='key_compromise'),
            _entry(100, reason='ca_compromise'),
        ])
        with self.assertRaises(crlview.DuplicateCRLEntryError):
            crlview.compose_crls(base, None, EVALUATION_TIME)

    def test_base_only_composition(self):
        base = _make_crl(ISSUER_A, 5, [_entry(100, reason='superseded')])
        view = crlview.compose_crls(base, None, EVALUATION_TIME)
        self.assertIsNone(view.delta_crl_number)
        self.assertTrue(view.is_revoked(ISSUER_A, 100))
