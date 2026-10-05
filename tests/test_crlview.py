# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys

from datetime import datetime

from asn1crypto import core, crl, crlview, x509
from asn1crypto.util import timezone

from ._unittest_compat import patch

patch()


def _dt(month, day, hour=0):
    return datetime(2026, month, day, hour, tzinfo=timezone.utc)


CA1_NAME = x509.Name.build({'common_name': 'Test CA 1'})
CA2_NAME = x509.Name.build({'common_name': 'Test CA 2'})

THIS_UPDATE = _dt(1, 1)
NEXT_UPDATE = _dt(2, 1)
EVALUATION_TIME = _dt(1, 15)


def _make_extension(extn_id, parsed_value, critical=False):
    extension = crl.TBSCertListExtension()
    extension['extn_id'] = extn_id
    extension['critical'] = critical
    extension['extn_value'] = parsed_value
    return extension


def _make_entry_extension(extn_id, parsed_value, critical=False):
    extension = crl.CRLEntryExtension()
    extension['extn_id'] = extn_id
    extension['critical'] = critical
    extension['extn_value'] = parsed_value
    return extension


def _make_entry(serial_number, revocation_date, reason=None, certificate_issuer=None):
    extensions = []
    if reason is not None:
        extensions.append(_make_entry_extension('crl_reason', crl.CRLReason(reason)))
    if certificate_issuer is not None:
        general_names = x509.GeneralNames([
            x509.GeneralName('directory_name', certificate_issuer)
        ])
        extensions.append(_make_entry_extension('certificate_issuer', general_names, critical=True))
    entry = {
        'user_certificate': serial_number,
        'revocation_date': {'utc_time': revocation_date},
    }
    if extensions:
        entry['crl_entry_extensions'] = extensions
    return crl.RevokedCertificate(entry)


def _make_crl(issuer, crl_number, entries, this_update=THIS_UPDATE, next_update=NEXT_UPDATE,
              delta_indicator=None, aki=None, idp=None):
    extensions = []
    if crl_number is not None:
        extensions.append(_make_extension('crl_number', core.Integer(crl_number)))
    if delta_indicator is not None:
        extensions.append(_make_extension('delta_crl_indicator', core.Integer(delta_indicator), critical=True))
    if aki is not None:
        extensions.append(_make_extension(
            'authority_key_identifier',
            x509.AuthorityKeyIdentifier({'key_identifier': aki})
        ))
    if idp is not None:
        extensions.append(_make_extension('issuing_distribution_point', idp, critical=True))
    tbs_cert_list = {
        'version': 'v2',
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': issuer,
        'this_update': {'utc_time': this_update},
        'revoked_certificates': entries,
        'crl_extensions': extensions,
    }
    if next_update is not None:
        tbs_cert_list['next_update'] = {'utc_time': next_update}
    return crl.CertificateList({
        'tbs_cert_list': tbs_cert_list,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x01' * 16,
    })


class CRLViewTests(unittest.TestCase):

    def test_compose_base_only(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(100, _dt(1, 2), reason='key_compromise'),
            _make_entry(101, _dt(1, 3)),
        ])

        view = crlview.ComposedCRLView.compose(base_crl, evaluation_time=EVALUATION_TIME)

        self.assertFalse(view.delta_applied)
        self.assertEqual(5, view.crl_number)
        self.assertEqual(2, len(view))

        status = view.status(CA1_NAME, 100)
        self.assertTrue(status.revoked)
        self.assertEqual('base', status.source)
        self.assertEqual('key_compromise', status.record.reason)
        self.assertEqual(_dt(1, 2), status.record.revocation_date)

        status = view.status(CA1_NAME, 101)
        self.assertTrue(status.revoked)
        self.assertIsNone(status.record.reason)

        status = view.status(CA1_NAME, 999)
        self.assertFalse(status.revoked)
        self.assertIsNone(status.record)
        self.assertIsNone(status.source)

    def test_delta_adds_revocation(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(100, _dt(1, 2), reason='key_compromise'),
        ])
        delta_crl = _make_crl(CA1_NAME, 6, [
            _make_entry(200, _dt(1, 10), reason='cessation_of_operation'),
        ], delta_indicator=5)

        view = crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

        self.assertTrue(view.delta_applied)
        self.assertEqual(6, view.crl_number)
        self.assertEqual(5, view.base_crl_number)
        self.assertEqual(6, view.delta_crl_number)
        self.assertEqual(2, len(view))

        status = view.status(CA1_NAME, 100)
        self.assertTrue(status.revoked)
        self.assertEqual('base', status.source)

        status = view.status(CA1_NAME, 200)
        self.assertTrue(status.revoked)
        self.assertEqual('delta', status.source)
        self.assertEqual('cessation_of_operation', status.record.reason)

    def test_delta_remove_from_crl_restores(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(100, _dt(1, 2), reason='key_compromise'),
            _make_entry(101, _dt(1, 3)),
        ])
        delta_crl = _make_crl(CA1_NAME, 6, [
            _make_entry(100, _dt(1, 10), reason='remove_from_crl'),
        ], delta_indicator=5)

        view = crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

        self.assertEqual(1, len(view))

        status = view.status(CA1_NAME, 100)
        self.assertFalse(status.revoked)
        self.assertIsNone(status.record)
        self.assertEqual('delta', status.source)

        status = view.status(CA1_NAME, 101)
        self.assertTrue(status.revoked)
        self.assertEqual('base', status.source)

    def test_indirect_crl_issuer_switch_same_serial(self):
        idp = crl.IssuingDistributionPoint({'indirect_crl': True})
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(500, _dt(1, 2), reason='key_compromise'),
            _make_entry(500, _dt(1, 3), certificate_issuer=CA2_NAME),
        ], idp=idp)
        delta_crl = _make_crl(CA1_NAME, 6, [
            _make_entry(500, _dt(1, 10), reason='remove_from_crl', certificate_issuer=CA2_NAME),
        ], delta_indicator=5, idp=idp)

        view = crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

        # The removeFromCRL entry for CA2's serial 500 must not remove
        # CA1's entry with the same serial number
        status = view.status(CA1_NAME, 500)
        self.assertTrue(status.revoked)
        self.assertEqual('base', status.source)
        self.assertEqual(CA1_NAME, status.record.issuer)

        status = view.status(CA2_NAME, 500)
        self.assertFalse(status.revoked)
        self.assertEqual('delta', status.source)

    def test_indirect_crl_issuer_persists_for_subsequent_entries(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(500, _dt(1, 2), certificate_issuer=CA2_NAME),
            _make_entry(501, _dt(1, 3)),
        ])

        view = crlview.ComposedCRLView.compose(base_crl, evaluation_time=EVALUATION_TIME)

        # No certificateIssuer on the second entry means it keeps the
        # issuer from the previous entry
        self.assertTrue(view.status(CA2_NAME, 500).revoked)
        self.assertTrue(view.status(CA2_NAME, 501).revoked)
        self.assertFalse(view.status(CA1_NAME, 501).revoked)

    def test_stale_base_crl(self):
        base_crl = _make_crl(CA1_NAME, 5, [])

        with self.assertRaises(crlview.CRLStaleError):
            crlview.ComposedCRLView.compose(base_crl, evaluation_time=_dt(2, 2))

    def test_stale_delta_crl(self):
        base_crl = _make_crl(CA1_NAME, 5, [])
        delta_crl = _make_crl(
            CA1_NAME, 6, [],
            this_update=_dt(1, 5),
            next_update=_dt(1, 10),
            delta_indicator=5
        )

        with self.assertRaises(crlview.CRLStaleError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_not_yet_valid_crl(self):
        base_crl = _make_crl(CA1_NAME, 5, [])

        with self.assertRaises(crlview.CRLNotYetValidError):
            crlview.ComposedCRLView.compose(base_crl, evaluation_time=_dt(1, 1).replace(year=2025))

    def test_naive_evaluation_time(self):
        base_crl = _make_crl(CA1_NAME, 5, [])

        with self.assertRaises(ValueError):
            crlview.ComposedCRLView.compose(base_crl, evaluation_time=datetime(2026, 1, 15))

    def test_delta_indicator_mismatch(self):
        base_crl = _make_crl(CA1_NAME, 5, [])
        delta_crl = _make_crl(CA1_NAME, 7, [], delta_indicator=4)

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_delta_missing_indicator(self):
        base_crl = _make_crl(CA1_NAME, 5, [])
        delta_crl = _make_crl(CA1_NAME, 6, [])

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_base_with_delta_indicator_rejected(self):
        base_crl = _make_crl(CA1_NAME, 5, [], delta_indicator=4)
        delta_crl = _make_crl(CA1_NAME, 6, [], delta_indicator=5)

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_delta_issuer_mismatch(self):
        base_crl = _make_crl(CA1_NAME, 5, [])
        delta_crl = _make_crl(CA2_NAME, 6, [], delta_indicator=5)

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_delta_authority_key_identifier_mismatch(self):
        base_crl = _make_crl(CA1_NAME, 5, [], aki=b'\x01' * 20)
        delta_crl = _make_crl(CA1_NAME, 6, [], delta_indicator=5, aki=b'\x02' * 20)

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_delta_issuing_distribution_point_mismatch(self):
        base_idp = crl.IssuingDistributionPoint({'indirect_crl': True})
        delta_idp = crl.IssuingDistributionPoint({'indirect_crl': False})
        base_crl = _make_crl(CA1_NAME, 5, [], idp=base_idp)
        delta_crl = _make_crl(CA1_NAME, 6, [], delta_indicator=5, idp=delta_idp)

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_delta_missing_issuing_distribution_point(self):
        base_crl = _make_crl(CA1_NAME, 5, [], idp=crl.IssuingDistributionPoint({'indirect_crl': True}))
        delta_crl = _make_crl(CA1_NAME, 6, [], delta_indicator=5)

        with self.assertRaises(crlview.DeltaCRLMismatchError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_duplicate_conflicting_entries(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(100, _dt(1, 2), reason='key_compromise'),
        ])
        delta_crl = _make_crl(CA1_NAME, 6, [
            _make_entry(100, _dt(1, 10), reason='superseded'),
        ], delta_indicator=5)

        with self.assertRaises(crlview.DuplicateCRLEntryError):
            crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

    def test_duplicate_identical_entries_tolerated(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(100, _dt(1, 2), reason='key_compromise'),
        ])
        delta_crl = _make_crl(CA1_NAME, 6, [
            _make_entry(100, _dt(1, 2), reason='key_compromise'),
        ], delta_indicator=5)

        view = crlview.ComposedCRLView.compose(base_crl, delta_crl, EVALUATION_TIME)

        self.assertEqual(1, len(view))
        self.assertTrue(view.status(CA1_NAME, 100).revoked)

    def test_remove_from_crl_in_base_rejected(self):
        base_crl = _make_crl(CA1_NAME, 5, [
            _make_entry(100, _dt(1, 2), reason='remove_from_crl'),
        ])

        with self.assertRaises(crlview.CRLCompositionError):
            crlview.ComposedCRLView.compose(base_crl, evaluation_time=EVALUATION_TIME)
