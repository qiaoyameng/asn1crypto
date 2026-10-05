# coding: utf-8

"""
Read-only composition of a complete (base) CRL with a delta CRL into a
queryable, current revocation view. Exports the following items:

 - CRLCompositionError()
 - CRLNotYetValidError()
 - CRLExpiredError()
 - DeltaCRLMismatchError()
 - DuplicateCRLEntryError()
 - RevocationRecord()
 - CompositeCRLView()
 - compose_crls()

The composition never re-encodes or re-signs a CRL. Instead it produces a
CompositeCRLView that records, for every revoked certificate, the entry data
and which source CRL (base or delta) the entry came from. Callers are
expected to have already verified the signatures on the CRL objects that
are passed in.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from ._errors import unwrap
from ._ordereddict import OrderedDict
from .crl import CertificateList
from .util import timezone
from .x509 import Name


class CRLCompositionError(ValueError):
    """
    Base exception for errors while composing a base CRL with a delta CRL
    """

    pass


class CRLNotYetValidError(CRLCompositionError):
    """
    The evaluation time is before the thisUpdate time of one of the CRLs
    """

    pass


class CRLExpiredError(CRLCompositionError):
    """
    The evaluation time is after the nextUpdate time of one of the CRLs
    """

    pass


class DeltaCRLMismatchError(CRLCompositionError):
    """
    The delta CRL does not apply to the provided base CRL
    """

    pass


class DuplicateCRLEntryError(CRLCompositionError):
    """
    A single CRL contains two conflicting entries for the same certificate
    """

    pass


class RevocationRecord(object):
    """
    An immutable record describing a single revoked certificate within a
    CompositeCRLView, including which source CRL the entry came from
    """

    _issuer = None
    _serial_number = None
    _revocation_date = None
    _reason = None
    _invalidity_date = None
    _source = None

    def __init__(self, issuer, serial_number, revocation_date, reason, invalidity_date, source):
        """
        :param issuer:
            An asn1crypto.x509.Name object of the certificate issuer. For
            indirect CRLs this reflects the most recent certificateIssuer
            entry extension, not necessarily the CRL issuer.

        :param serial_number:
            An integer of the certificate serial number

        :param revocation_date:
            A datetime object of when the certificate was revoked

        :param reason:
            None or a unicode string of the CRL reason name, e.g.
            "key_compromise"

        :param invalidity_date:
            None or a datetime object of when the certificate became invalid

        :param source:
            A unicode string of either "base" or "delta" indicating which
            CRL the entry was taken from
        """

        self._issuer = issuer
        self._serial_number = serial_number
        self._revocation_date = revocation_date
        self._reason = reason
        self._invalidity_date = invalidity_date
        self._source = source

    @property
    def issuer(self):
        """
        :return:
            An asn1crypto.x509.Name object of the certificate issuer
        """

        return self._issuer

    @property
    def serial_number(self):
        """
        :return:
            An integer of the certificate serial number
        """

        return self._serial_number

    @property
    def revocation_date(self):
        """
        :return:
            A datetime object of when the certificate was revoked
        """

        return self._revocation_date

    @property
    def reason(self):
        """
        :return:
            None or a unicode string of the CRL reason name
        """

        return self._reason

    @property
    def invalidity_date(self):
        """
        :return:
            None or a datetime object of when the certificate became invalid
        """

        return self._invalidity_date

    @property
    def source(self):
        """
        :return:
            A unicode string of either "base" or "delta"
        """

        return self._source

    def __repr__(self):
        return '<RevocationRecord %s serial=%d reason=%s source=%s>' % (
            self._issuer.human_friendly,
            self._serial_number,
            self._reason,
            self._source,
        )


class CompositeCRLView(object):
    """
    A read-only, queryable view of a base CRL composed with a delta CRL.
    This is not a CertificateList and can not be dumped or re-signed - it
    only exposes revocation status lookups and provenance information.
    """

    _issuer = None
    _evaluation_time = None
    _base_crl_number = None
    _delta_crl_number = None
    _records = None
    _index = None

    def __init__(self, issuer, evaluation_time, base_crl_number, delta_crl_number, records):
        """
        :param issuer:
            An asn1crypto.x509.Name object of the CRL issuer

        :param evaluation_time:
            A datetime object the view was composed for

        :param base_crl_number:
            An integer of the CRL number of the base CRL

        :param delta_crl_number:
            None or an integer of the CRL number of the delta CRL

        :param records:
            A list of RevocationRecord objects
        """

        self._issuer = issuer
        self._evaluation_time = evaluation_time
        self._base_crl_number = base_crl_number
        self._delta_crl_number = delta_crl_number
        self._records = tuple(records)
        self._index = {}
        for record in self._records:
            self._index[(record.issuer.dump(), record.serial_number)] = record

    @property
    def issuer(self):
        """
        :return:
            An asn1crypto.x509.Name object of the CRL issuer
        """

        return self._issuer

    @property
    def evaluation_time(self):
        """
        :return:
            A datetime object the view was composed for
        """

        return self._evaluation_time

    @property
    def base_crl_number(self):
        """
        :return:
            An integer of the CRL number of the base CRL
        """

        return self._base_crl_number

    @property
    def delta_crl_number(self):
        """
        :return:
            None or an integer of the CRL number of the delta CRL
        """

        return self._delta_crl_number

    @property
    def revoked_entries(self):
        """
        :return:
            A tuple of RevocationRecord objects for every certificate that
            is revoked in the composed view
        """

        return self._records

    def __len__(self):
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def get_status(self, issuer, serial_number):
        """
        Looks up the revocation status of a single certificate

        :param issuer:
            An asn1crypto.x509.Name object of the certificate issuer, or a
            dict suitable for asn1crypto.x509.Name.build()

        :param serial_number:
            An integer of the certificate serial number

        :return:
            None if the certificate is not revoked in the composed view,
            otherwise a RevocationRecord with the revocation details and
            the source CRL
        """

        if not isinstance(issuer, Name):
            issuer = Name.build(issuer)
        return self._index.get((issuer.dump(), serial_number))

    def is_revoked(self, issuer, serial_number):
        """
        :param issuer:
            An asn1crypto.x509.Name object of the certificate issuer, or a
            dict suitable for asn1crypto.x509.Name.build()

        :param serial_number:
            An integer of the certificate serial number

        :return:
            A bool of if the certificate is revoked in the composed view
        """

        return self.get_status(issuer, serial_number) is not None


def _normalize_time(value):
    """
    Ensures a datetime is timezone-aware so it can be compared with the
    times parsed from a CRL

    :param value:
        A datetime object

    :return:
        A timezone-aware datetime object
    """

    if not isinstance(value, datetime):
        raise TypeError(unwrap(
            '''
            evaluation_time must be a datetime object, not %s
            ''',
            type(value).__name__
        ))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _check_validity(cert_list, evaluation_time, label):
    """
    Ensures a CRL is valid at the evaluation time

    :param cert_list:
        An asn1crypto.crl.CertificateList object

    :param evaluation_time:
        A timezone-aware datetime object

    :param label:
        A unicode string of "base" or "delta" for error messages

    :raises:
        CRLNotYetValidError - when the evaluation time is before thisUpdate
        CRLExpiredError - when the evaluation time is after nextUpdate
    """

    tbs = cert_list['tbs_cert_list']
    this_update = tbs['this_update'].native
    if evaluation_time < this_update:
        raise CRLNotYetValidError(unwrap(
            '''
            The %s CRL is not yet valid at the evaluation time - thisUpdate
            is %s
            ''',
            label,
            this_update.isoformat()
        ))
    next_update = tbs['next_update'].native
    if next_update is not None and evaluation_time > next_update:
        raise CRLExpiredError(unwrap(
            '''
            The %s CRL is expired at the evaluation time - nextUpdate is %s
            ''',
            label,
            next_update.isoformat()
        ))


def _validate_delta_applies(base_crl, delta_crl):
    """
    Ensures a delta CRL may be applied to a base CRL by checking the issuer,
    authority key identifier, issuing distribution point and the CRL number
    and delta CRL indicator relationship

    :param base_crl:
        An asn1crypto.crl.CertificateList object of the complete CRL

    :param delta_crl:
        An asn1crypto.crl.CertificateList object of the delta CRL

    :raises:
        DeltaCRLMismatchError - when the delta CRL does not apply
    """

    delta_indicator = delta_crl.delta_crl_indicator_value
    if delta_indicator is None:
        raise DeltaCRLMismatchError(
            'The delta CRL is missing the delta CRL indicator extension'
        )

    if base_crl.issuer.dump() != delta_crl.issuer.dump():
        raise DeltaCRLMismatchError(
            'The delta CRL issuer does not match the base CRL issuer'
        )

    base_aki = base_crl.authority_key_identifier
    delta_aki = delta_crl.authority_key_identifier
    if base_aki != delta_aki:
        raise DeltaCRLMismatchError(
            'The delta CRL authority key identifier does not match the base CRL'
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
            'The delta CRL issuing distribution point does not match the base CRL'
        )

    base_number = base_crl.crl_number_value
    if base_number is None:
        raise DeltaCRLMismatchError(
            'The base CRL is missing the CRL number extension'
        )
    delta_number = delta_crl.crl_number_value
    if delta_number is None:
        raise DeltaCRLMismatchError(
            'The delta CRL is missing the CRL number extension'
        )
    base_number = base_number.native
    delta_number = delta_number.native
    delta_indicator = delta_indicator.native

    if delta_indicator > base_number:
        raise DeltaCRLMismatchError(unwrap(
            '''
            The delta CRL indicator %d refers to a base CRL newer than the
            provided base CRL number %d
            ''',
            delta_indicator,
            base_number
        ))
    if delta_number <= base_number:
        raise DeltaCRLMismatchError(unwrap(
            '''
            The delta CRL number %d is not greater than the base CRL number
            %d
            ''',
            delta_number,
            base_number
        ))


def _entry_records(cert_list, source):
    """
    Yields RevocationRecord objects for the entries of a CRL, tracking the
    certificateIssuer entry extension of indirect CRLs so that every record
    is attributed to the correct certificate issuer

    :param cert_list:
        An asn1crypto.crl.CertificateList object

    :param source:
        A unicode string of "base" or "delta"

    :return:
        A generator of RevocationRecord objects
    """

    tbs = cert_list['tbs_cert_list']
    current_issuer = tbs['issuer']
    for entry in tbs['revoked_certificates']:
        if entry.certificate_issuer_value is not None:
            issuer_name = entry.issuer_name
            if issuer_name is None:
                raise CRLCompositionError(unwrap(
                    '''
                    A %s CRL entry contains a certificateIssuer extension
                    without a directoryName
                    ''',
                    source
                ))
            current_issuer = issuer_name
        reason = entry.crl_reason_value
        invalidity_date = entry.invalidity_date_value
        yield RevocationRecord(
            issuer=current_issuer,
            serial_number=entry['user_certificate'].native,
            revocation_date=entry['revocation_date'].native,
            reason=reason.native if reason is not None else None,
            invalidity_date=invalidity_date.native if invalidity_date is not None else None,
            source=source,
        )


def _records_conflict(first, second):
    """
    :param first:
        A RevocationRecord object

    :param second:
        A RevocationRecord object

    :return:
        A bool of if two records for the same certificate disagree
    """

    return (
        first.revocation_date != second.revocation_date or
        first.reason != second.reason
    )


def compose_crls(base_crl, delta_crl, evaluation_time):
    """
    Composes a complete (base) CRL with a delta CRL into a read-only view of
    the current revocation state. The signatures on the CRL objects must
    have already been verified by the caller - this function only checks the
    applicability of the delta CRL and merges the entries.

    Entry identity is the pair of certificate issuer and serial number, so
    for indirect CRLs a removeFromCRL entry only reinstates a certificate
    from the same issuer, never a different issuer's certificate that
    happens to share the serial number.

    :param base_crl:
        An asn1crypto.crl.CertificateList object of the complete CRL

    :param delta_crl:
        None or an asn1crypto.crl.CertificateList object of the delta CRL

    :param evaluation_time:
        A datetime object of the time the revocation state is evaluated at

    :return:
        A CompositeCRLView object

    :raises:
        CRLNotYetValidError - when a CRL is not yet valid at evaluation_time
        CRLExpiredError - when a CRL is expired at evaluation_time
        DeltaCRLMismatchError - when the delta CRL does not apply to the base CRL
        DuplicateCRLEntryError - when a CRL contains conflicting entries for
            the same certificate
    """

    if not isinstance(base_crl, CertificateList):
        raise TypeError(unwrap(
            '''
            base_crl must be an asn1crypto.crl.CertificateList object, not %s
            ''',
            type(base_crl).__name__
        ))
    if delta_crl is not None and not isinstance(delta_crl, CertificateList):
        raise TypeError(unwrap(
            '''
            delta_crl must be an asn1crypto.crl.CertificateList object, not %s
            ''',
            type(delta_crl).__name__
        ))

    evaluation_time = _normalize_time(evaluation_time)

    _check_validity(base_crl, evaluation_time, 'base')

    if base_crl.delta_crl_indicator_value is not None:
        raise DeltaCRLMismatchError(
            'The base CRL contains a delta CRL indicator and is itself a delta CRL'
        )

    base_number = base_crl.crl_number_value
    if base_number is None:
        raise DeltaCRLMismatchError(
            'The base CRL is missing the CRL number extension'
        )
    base_number = base_number.native

    records = OrderedDict()

    def merge(record, allow_update):
        key = (record.issuer.dump(), record.serial_number)
        if record.reason == 'remove_from_crl':
            # Scoped by (issuer, serial number), so a certificate from one
            # issuer is never removed by another issuer's entry
            records.pop(key, None)
            return
        existing = records.get(key)
        if existing is not None:
            if existing.source == record.source and _records_conflict(existing, record):
                raise DuplicateCRLEntryError(unwrap(
                    '''
                    The %s CRL contains conflicting entries for serial number
                    %d from issuer %s
                    ''',
                    record.source,
                    record.serial_number,
                    record.issuer.human_friendly
                ))
            if not allow_update:
                return
        records[key] = record

    for record in _entry_records(base_crl, 'base'):
        merge(record, allow_update=False)

    delta_number = None
    if delta_crl is not None:
        _check_validity(delta_crl, evaluation_time, 'delta')
        _validate_delta_applies(base_crl, delta_crl)
        delta_number = delta_crl.crl_number_value.native
        for record in _entry_records(delta_crl, 'delta'):
            # A delta CRL entry may update the reason or date of a base CRL
            # entry, so it replaces the existing record
            merge(record, allow_update=True)

    return CompositeCRLView(
        issuer=base_crl.issuer,
        evaluation_time=evaluation_time,
        base_crl_number=base_number,
        delta_crl_number=delta_number,
        records=list(records.values()),
    )
