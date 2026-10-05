# coding: utf-8

"""
Read-only composition of a base CRL and an optional delta CRL into a
queryable revocation view. The caller is responsible for verifying the
signatures on the CRL objects before composing them - this module never
re-signs or emits a synthetic CRL, it only exposes the merged state. Exports
the following items:

 - ComposedCRLView()
 - RevocationRecord()
 - RevocationStatus()
 - CRLCompositionError()
 - CRLNotYetValidError()
 - CRLStaleError()
 - DeltaCRLMismatchError()
 - DuplicateCRLEntryError()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from ._errors import unwrap
from ._ordereddict import OrderedDict
from ._types import type_name
from .crl import CertificateList
from .x509 import Name


class CRLCompositionError(ValueError):
    """
    Base exception for errors encountered while composing a CRL view
    """


class CRLNotYetValidError(CRLCompositionError):
    """
    The evaluation time is before the this_update time of one of the CRLs
    """


class CRLStaleError(CRLCompositionError):
    """
    The evaluation time is after the next_update time of one of the CRLs
    """


class DeltaCRLMismatchError(CRLCompositionError):
    """
    The delta CRL does not match the base CRL it claims to update
    """


class DuplicateCRLEntryError(CRLCompositionError):
    """
    Two conflicting revocation entries exist for the same issuer and serial
    """


class RevocationRecord(object):
    """
    A single revocation in a composed view, with provenance
    """

    # An asn1crypto.x509.Name object for the issuer of the certificate
    issuer = None

    # An integer of the certificate serial number
    serial_number = None

    # A timezone-aware datetime object of when the certificate was revoked
    revocation_date = None

    # None or a unicode string of the CRL reason name, e.g. 'key_compromise'
    reason = None

    # None or a timezone-aware datetime object of the invalidity date
    invalidity_date = None

    # A unicode string of 'base' or 'delta' - which CRL the entry came from
    source = None

    def __init__(self, issuer, serial_number, revocation_date, reason, invalidity_date, source):
        self.issuer = issuer
        self.serial_number = serial_number
        self.revocation_date = revocation_date
        self.reason = reason
        self.invalidity_date = invalidity_date
        self.source = source

    def __repr__(self):
        return '<RevocationRecord %s issued by %s, source %s>' % (
            self.serial_number,
            self.issuer.human_friendly,
            self.source,
        )


class RevocationStatus(object):
    """
    The result of querying a ComposedCRLView for a certificate
    """

    # An asn1crypto.x509.Name object for the issuer of the certificate
    issuer = None

    # An integer of the certificate serial number
    serial_number = None

    # A bool - if the certificate is revoked at the evaluation time
    revoked = None

    # None or a RevocationRecord object with details of the revocation
    record = None

    # None, 'base' or 'delta' - which CRL determined this status. 'delta'
    # with revoked set to False means a removeFromCRL delta entry restored
    # the certificate.
    source = None

    def __init__(self, issuer, serial_number, revoked, record, source):
        self.issuer = issuer
        self.serial_number = serial_number
        self.revoked = revoked
        self.record = record
        self.source = source

    def __repr__(self):
        return '<RevocationStatus %s revoked=%s, source %s>' % (
            self.serial_number,
            self.revoked,
            self.source,
        )


def _name_key(name):
    """
    Creates a canonical identity for an issuer name

    :param name:
        An asn1crypto.x509.Name object

    :return:
        A byte string of the DER encoding
    """

    # A directoryName extracted from a certificateIssuer general name carries
    # an explicit tag that must be removed to compare equal to a plain Name
    return name.untag().dump()


def _check_freshness(cert_list, label, evaluation_time):
    """
    Ensures a CRL is valid at the evaluation time

    :param cert_list:
        An asn1crypto.crl.CertificateList object

    :param label:
        A unicode string of 'base' or 'delta', used in error messages

    :param evaluation_time:
        A timezone-aware datetime object

    :raises:
        CRLNotYetValidError, CRLStaleError
    """

    tbs_cert_list = cert_list['tbs_cert_list']
    this_update = tbs_cert_list['this_update'].native
    if evaluation_time < this_update:
        raise CRLNotYetValidError(unwrap(
            '''
            The %s CRL is not yet valid at the evaluation time - this_update
            is %s
            ''',
            label,
            this_update
        ))
    next_update = tbs_cert_list['next_update'].native
    if next_update is not None and evaluation_time > next_update:
        raise CRLStaleError(unwrap(
            '''
            The %s CRL is stale at the evaluation time - next_update is %s
            ''',
            label,
            next_update
        ))


def _validate_delta_relationship(base_crl, delta_crl):
    """
    Ensures a delta CRL applies to a base CRL, per RFC 5280

    :param base_crl:
        An asn1crypto.crl.CertificateList object that is a complete CRL

    :param delta_crl:
        An asn1crypto.crl.CertificateList object that is a delta CRL

    :raises:
        DeltaCRLMismatchError
    """

    if base_crl.delta_crl_indicator_value is not None:
        raise DeltaCRLMismatchError(
            'The base CRL contains a delta CRL indicator, so it is not a complete CRL'
        )

    delta_indicator = delta_crl.delta_crl_indicator_value
    if delta_indicator is None:
        raise DeltaCRLMismatchError(
            'The delta CRL does not contain a delta CRL indicator extension'
        )

    base_number = base_crl.crl_number_value
    if base_number is None:
        raise DeltaCRLMismatchError(
            'The base CRL does not contain a CRL number extension, so a delta '
            'CRL can not be matched to it'
        )

    if delta_indicator.native != base_number.native:
        raise DeltaCRLMismatchError(unwrap(
            '''
            The delta CRL indicator (%s) does not match the base CRL
            number (%s)
            ''',
            delta_indicator.native,
            base_number.native
        ))

    if _name_key(delta_crl.issuer) != _name_key(base_crl.issuer):
        raise DeltaCRLMismatchError(
            'The delta CRL issuer does not match the base CRL issuer'
        )

    base_aki = base_crl.authority_key_identifier
    delta_aki = delta_crl.authority_key_identifier
    if base_aki is not None and delta_aki is not None and base_aki != delta_aki:
        raise DeltaCRLMismatchError(
            'The delta CRL authority key identifier does not match the base '
            'CRL authority key identifier'
        )

    base_idp = base_crl.issuing_distribution_point_value
    delta_idp = delta_crl.issuing_distribution_point_value
    if (base_idp is None) != (delta_idp is None):
        raise DeltaCRLMismatchError(
            'Only one of the base CRL and delta CRL contains an issuing '
            'distribution point extension'
        )
    if base_idp is not None and base_idp.dump() != delta_idp.dump():
        raise DeltaCRLMismatchError(
            'The delta CRL issuing distribution point does not match the '
            'base CRL issuing distribution point'
        )


def _absorb_entries(entries, removals, cert_list, source):
    """
    Merges the revoked certificates of a CRL into an ordered mapping keyed
    by (issuer, serial number). For indirect CRLs, the certificateIssuer
    entry extension changes the issuer attributed to subsequent entries.

    :param entries:
        An OrderedDict of (byte string, int) -> RevocationRecord

    :param removals:
        An OrderedDict of (byte string, int) -> RevocationRecord, tracking
        removeFromCRL delta entries for provenance

    :param cert_list:
        An asn1crypto.crl.CertificateList object

    :param source:
        A unicode string of 'base' or 'delta'

    :raises:
        CRLCompositionError, DuplicateCRLEntryError
    """

    current_issuer = cert_list.issuer

    for revoked_cert in cert_list['tbs_cert_list']['revoked_certificates']:
        if revoked_cert.certificate_issuer_value is not None:
            issuer_name = revoked_cert.issuer_name
            if issuer_name is None:
                raise CRLCompositionError(
                    'A certificateIssuer entry extension does not contain a '
                    'directoryName, so the entry issuer can not be determined'
                )
            current_issuer = issuer_name.untag()

        serial_number = revoked_cert['user_certificate'].native
        key = (_name_key(current_issuer), serial_number)

        crl_reason = revoked_cert.crl_reason_value
        reason = crl_reason.native if crl_reason is not None else None

        if reason == 'remove_from_crl':
            if source != 'delta':
                raise CRLCompositionError(
                    'The removeFromCRL reason is only valid in a delta CRL'
                )
            # Keyed by issuer and serial, so a removeFromCRL entry can never
            # delete a different issuer's certificate with the same serial
            if key in entries:
                del entries[key]
                removals[key] = RevocationRecord(
                    current_issuer,
                    serial_number,
                    revoked_cert['revocation_date'].native,
                    reason,
                    None,
                    source
                )
            continue

        invalidity_date = revoked_cert.invalidity_date_value
        record = RevocationRecord(
            current_issuer,
            serial_number,
            revoked_cert['revocation_date'].native,
            reason,
            invalidity_date.native if invalidity_date is not None else None,
            source
        )

        existing = entries.get(key)
        if existing is not None:
            if existing.revocation_date == record.revocation_date and existing.reason == record.reason:
                # An identical repeat of the same entry is harmless
                continue
            raise DuplicateCRLEntryError(unwrap(
                '''
                Conflicting revocation entries for serial number %s issued
                by %s
                ''',
                serial_number,
                current_issuer.human_friendly
            ))

        entries[key] = record


class ComposedCRLView(object):
    """
    A read-only, queryable view of a base CRL with an optional delta CRL
    applied on top, evaluated at a specific point in time
    """

    # An asn1crypto.x509.Name object for the issuer of the CRLs
    issuer = None

    # A timezone-aware datetime object the view was evaluated at
    evaluation_time = None

    # A timezone-aware datetime object - from the delta CRL when applied
    this_update = None

    # None or a timezone-aware datetime object - from the delta when applied
    next_update = None

    # None or an integer - the CRL number of the delta CRL when applied,
    # otherwise of the base CRL
    crl_number = None

    # None or an integer - the CRL number of the base CRL
    base_crl_number = None

    # None or an integer - the CRL number of the delta CRL
    delta_crl_number = None

    # A bool - if a delta CRL was applied
    delta_applied = None

    # A tuple of RevocationRecord objects
    entries = None

    _index = None
    _removals = None

    @classmethod
    def compose(cls, base_crl, delta_crl=None, evaluation_time=None):
        """
        Composes a base CRL and an optional delta CRL into a revocation view.
        Both CRL objects must already have had their signatures verified by
        the caller.

        :param base_crl:
            An asn1crypto.crl.CertificateList object that is a complete CRL

        :param delta_crl:
            None or an asn1crypto.crl.CertificateList object that is a delta
            CRL for the base CRL

        :param evaluation_time:
            A timezone-aware datetime object that the revocation state is
            evaluated at

        :raises:
            CRLNotYetValidError, CRLStaleError, DeltaCRLMismatchError,
            DuplicateCRLEntryError, CRLCompositionError

        :return:
            A ComposedCRLView object
        """

        if not isinstance(base_crl, CertificateList):
            raise TypeError(unwrap(
                '''
                base_crl must be an instance of asn1crypto.crl.CertificateList,
                not %s
                ''',
                type_name(base_crl)
            ))
        if delta_crl is not None and not isinstance(delta_crl, CertificateList):
            raise TypeError(unwrap(
                '''
                delta_crl must be an instance of asn1crypto.crl.CertificateList,
                not %s
                ''',
                type_name(delta_crl)
            ))
        if not isinstance(evaluation_time, datetime):
            raise TypeError(unwrap(
                '''
                evaluation_time must be a timezone-aware datetime object,
                not %s
                ''',
                type_name(evaluation_time)
            ))
        if evaluation_time.tzinfo is None:
            raise ValueError('evaluation_time must be timezone-aware')

        _check_freshness(base_crl, 'base', evaluation_time)
        if delta_crl is not None:
            _check_freshness(delta_crl, 'delta', evaluation_time)
            _validate_delta_relationship(base_crl, delta_crl)

        entries = OrderedDict()
        removals = OrderedDict()
        _absorb_entries(entries, removals, base_crl, 'base')
        if delta_crl is not None:
            _absorb_entries(entries, removals, delta_crl, 'delta')

        freshest = delta_crl if delta_crl is not None else base_crl

        view = cls()
        view.issuer = base_crl.issuer
        view.evaluation_time = evaluation_time
        view.this_update = freshest['tbs_cert_list']['this_update'].native
        view.next_update = freshest['tbs_cert_list']['next_update'].native
        crl_number = freshest.crl_number_value
        view.crl_number = crl_number.native if crl_number is not None else None
        base_number = base_crl.crl_number_value
        view.base_crl_number = base_number.native if base_number is not None else None
        if delta_crl is not None:
            delta_number = delta_crl.crl_number_value
            view.delta_crl_number = delta_number.native if delta_number is not None else None
        view.delta_applied = delta_crl is not None
        view.entries = tuple(entries.values())
        view._index = entries
        view._removals = removals
        return view

    def status(self, issuer, serial_number):
        """
        Looks up the revocation status of a single certificate

        :param issuer:
            An asn1crypto.x509.Name object for the issuer of the certificate

        :param serial_number:
            An integer of the certificate serial number

        :return:
            A RevocationStatus object
        """

        if not isinstance(issuer, Name):
            raise TypeError(unwrap(
                '''
                issuer must be an instance of asn1crypto.x509.Name, not %s
                ''',
                type_name(issuer)
            ))

        key = (_name_key(issuer), serial_number)
        record = self._index.get(key)
        if record is not None:
            return RevocationStatus(issuer, serial_number, True, record, record.source)
        if key in self._removals:
            return RevocationStatus(issuer, serial_number, False, None, 'delta')
        return RevocationStatus(issuer, serial_number, False, None, None)

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)
