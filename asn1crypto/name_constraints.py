# coding: utf-8

"""
Evaluates X.509 name constraints (RFC 5280, Section 4.2.1.10) against a
single name.

This module is a standalone tool: given the name constraints extensions of a
certification path, in chain order, and a name to check, it determines if the
name is acceptable, and if not, which specific constraint is responsible. It
does not perform certification path validation - signature verification, the
validity period, trust anchor selection and similar concerns are all out of
scope.

The semantics implemented are:

 - Permitted subtrees narrow level-by-level: a name must fall within the
   permitted subtrees of every level that defines permitted subtrees for the
   name's form
 - Excluded subtrees accumulate: a name excluded at any level is rejected
 - dNSName constraints match on label boundaries, with a leading period
   restricting matches to proper sub-domains
 - rfc822Name constraints may be a complete mailbox, all mailboxes at a
   host, or all mailboxes in a domain (leading period)
 - iPAddress constraints are an address and mask; masks must be contiguous
 - directoryName constraints match when the constraint's RDN sequence is a
   prefix of the name's RDN sequence
 - Non-default minimum and maximum values are not supported and fail
   explicitly
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._types import type_name
from .x509 import GeneralName, NameConstraints


__all__ = [
    'NameConstraintVerdict',
    'UnsupportedNameConstraint',
    'evaluate_name_constraints',
]


class UnsupportedNameConstraint(ValueError):
    """
    Raised when a name constraint, or the name being checked, uses a feature
    that is not supported: a non-default minimum or maximum, an iPAddress
    constraint with a non-contiguous mask or invalid length, or a name form
    other than dNSName, rfc822Name, iPAddress or directoryName.
    """

    pass


class NameConstraintVerdict(object):
    """
    The result of evaluating a chain of name constraints against a name.

    When the name is acceptable, allowed is True and every other attribute is
    None. When the name is rejected, level identifies the entry in the chain
    of constraints that actually took effect, kind is one of the unicode
    strings "excluded" or "permitted", and subtree (for an exclusion) or
    subtrees (for a permitted-subtree failure) identifies the responsible
    constraint.
    """

    # A bool - if the name is acceptable under the constraints
    allowed = None

    # None, or an integer index into the chain of constraints identifying
    # the level whose constraint rejected the name
    level = None

    # None, or one of the unicode strings "excluded" or "permitted"
    kind = None

    # None, or the x509.GeneralSubtree object whose excluded subtree matched
    # the name
    subtree = None

    # None, or a tuple of x509.GeneralSubtree objects - the permitted
    # subtrees of the effective level that the name failed to fall within
    subtrees = None

    # None, or a unicode string explaining the rejection
    reason = None

    def __init__(self, allowed, level=None, kind=None, subtree=None,
                 subtrees=None, reason=None):
        self.allowed = allowed
        self.level = level
        self.kind = kind
        self.subtree = subtree
        self.subtrees = subtrees
        self.reason = reason

    def __nonzero__(self):
        return self.allowed

    def __bool__(self):
        return self.allowed

    def __repr__(self):
        if self.allowed:
            return '<NameConstraintVerdict allowed>'
        return '<NameConstraintVerdict rejected at level %s: %s>' % (
            self.level,
            self.reason,
        )


def evaluate_name_constraints(chain, name):
    """
    Evaluates a chain of name constraints against a single name.

    :param chain:
        A list (or tuple) of x509.NameConstraints objects, in chain order
        (trust anchor first). Entries may be None for certificates without a
        name constraints extension.

    :param name:
        An x509.GeneralName object of one of the supported name forms:
        dns_name, rfc822_name, ip_address or directory_name.

    :raises UnsupportedNameConstraint:
        When a constraint uses a non-default minimum or maximum, an iPAddress
        constraint has a non-contiguous mask or invalid length, or the name
        being checked is of an unsupported form.

    :return:
        A NameConstraintVerdict object
    """

    if not isinstance(name, GeneralName):
        raise TypeError(
            'name must be an x509.GeneralName object, not %s' % type_name(name)
        )

    matcher = _MATCHERS.get(name.name)
    if matcher is None:
        raise UnsupportedNameConstraint(
            'Evaluating name constraints against the name form "%s" is not '
            'supported - only dns_name, rfc822_name, ip_address and '
            'directory_name are' % name.name
        )

    levels = []
    for level, constraints in enumerate(chain):
        if constraints is None:
            continue
        if not isinstance(constraints, NameConstraints):
            raise TypeError(
                'chain entries must be x509.NameConstraints objects or None, '
                'not %s' % type_name(constraints)
            )
        _validate_constraints(constraints, level)
        levels.append((level, constraints))

    for level, constraints in levels:
        for subtree in constraints['excluded_subtrees']:
            base = subtree['base']
            if base.name != name.name:
                continue
            if matcher(base, name):
                return NameConstraintVerdict(
                    allowed=False,
                    level=level,
                    kind='excluded',
                    subtree=subtree,
                    reason=(
                        'The name is within the excluded %s subtree "%s" '
                        'from chain level %d' % (
                            name.name,
                            _base_description(base),
                            level,
                        )
                    ),
                )

        relevant = tuple(
            subtree
            for subtree in constraints['permitted_subtrees']
            if subtree['base'].name == name.name
        )
        if not relevant:
            continue
        for subtree in relevant:
            if matcher(subtree['base'], name):
                break
        else:
            return NameConstraintVerdict(
                allowed=False,
                level=level,
                kind='permitted',
                subtrees=relevant,
                reason=(
                    'The name is not within any of the permitted %s '
                    'subtrees from chain level %d (%s)' % (
                        name.name,
                        level,
                        ', '.join(
                            '"%s"' % _base_description(subtree['base'])
                            for subtree in relevant
                        ),
                    )
                ),
            )

    return NameConstraintVerdict(allowed=True)


def _validate_constraints(constraints, level):
    """
    Ensures every subtree of a NameConstraints object uses only supported
    features, failing explicitly otherwise.

    :param constraints:
        An x509.NameConstraints object

    :param level:
        An integer of the constraints' position within the chain
    """

    for subtrees in (
        constraints['permitted_subtrees'],
        constraints['excluded_subtrees'],
    ):
        for subtree in subtrees:
            minimum = subtree['minimum'].native
            if minimum != 0:
                raise UnsupportedNameConstraint(
                    'Name constraints with a non-default minimum (%d) are '
                    'not supported (chain level %d)' % (minimum, level)
                )
            maximum = subtree['maximum'].native
            if maximum is not None:
                raise UnsupportedNameConstraint(
                    'Name constraints with a maximum (%d) are not supported '
                    '(chain level %d)' % (maximum, level)
                )
            base = subtree['base']
            if base.name == 'ip_address':
                _parse_ip_constraint(base.chosen.contents, level)


def _base_description(base):
    """
    Builds a human-readable description of a GeneralName constraint base

    :param base:
        An x509.GeneralName object

    :return:
        A unicode string
    """

    if base.name == 'directory_name':
        return base.chosen.human_friendly
    return base.chosen.native


def _dns_name_match(constraint, hostname):
    """
    Checks if a hostname satisfies a dNSName constraint

    :param constraint:
        A unicode string of the constraint

    :param hostname:
        A unicode string of the hostname to check

    :return:
        A boolean
    """

    constraint = constraint.lower()
    hostname = hostname.lower()
    if constraint.endswith('.'):
        constraint = constraint[:-1]
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    if constraint.startswith('.'):
        # A leading period restricts matches to proper sub-domains, so the
        # apex name itself is not acceptable
        suffix = constraint[1:]
        return bool(suffix) and hostname.endswith('.' + suffix)

    # Matching is performed on label boundaries, so "example.com" is
    # satisfied by "host.example.com" but never by "badexample.com"
    return hostname == constraint or hostname.endswith('.' + constraint)


def _rfc822_name_match(constraint, address):
    """
    Checks if a mail address satisfies an rfc822Name constraint

    :param constraint:
        A unicode string of the constraint

    :param address:
        A unicode string of the mail address to check

    :return:
        A boolean
    """

    if '@' in constraint:
        # A complete mail address constrains a single mailbox - the local
        # part must match exactly, while the host is case-insensitive
        constraint_local, _, constraint_host = constraint.rpartition('@')
        local, _, host = address.rpartition('@')
        return local == constraint_local and \
            host.lower() == constraint_host.lower()

    _, _, host = address.rpartition('@')
    if not host:
        return False

    if constraint.startswith('.'):
        # All mailboxes within a domain, but not at the apex host itself
        suffix = constraint[1:].lower()
        return bool(suffix) and host.lower().endswith('.' + suffix)

    # All mailboxes at a particular host
    return host.lower() == constraint.lower()


def _parse_ip_constraint(value, level):
    """
    Splits an iPAddress constraint into an address and a mask, ensuring the
    encoding is one this evaluator supports

    :param value:
        A byte string of the constraint contents

    :param level:
        An integer of the constraint's position within the chain, or None

    :return:
        A 2-element tuple of byte strings: (address, mask)
    """

    if len(value) == 8:
        address, mask = value[:4], value[4:]
    elif len(value) == 32:
        address, mask = value[:16], value[16:]
    else:
        raise UnsupportedNameConstraint(
            'iPAddress name constraints must be 8 bytes (IPv4) or 32 bytes '
            '(IPv6), not %d%s' % (len(value), _level_suffix(level))
        )

    if not _mask_is_contiguous(mask):
        raise UnsupportedNameConstraint(
            'iPAddress name constraints with a non-contiguous mask are not '
            'supported%s' % _level_suffix(level)
        )

    return address, mask


def _level_suffix(level):
    """
    Formats a chain level for inclusion in an error message

    :param level:
        An integer of the constraint's position within the chain, or None

    :return:
        A unicode string
    """

    if level is None:
        return ''
    return ' (chain level %d)' % level


def _mask_is_contiguous(mask):
    """
    Checks if an IP address mask consists of one or more 1 bits followed by
    zero or more 0 bits

    :param mask:
        A byte string of the mask

    :return:
        A boolean
    """

    seen_zero = False
    for byte in bytearray(mask):
        for bit in range(7, -1, -1):
            if (byte >> bit) & 1:
                if seen_zero:
                    return False
            else:
                seen_zero = True
    return True


def _ip_address_match(constraint, address):
    """
    Checks if an IP address satisfies an iPAddress constraint

    :param constraint:
        A byte string of the constraint contents (address and mask)

    :param address:
        A byte string of the address to check

    :return:
        A boolean
    """

    constraint_address, mask = _parse_ip_constraint(constraint, None)
    if len(address) != len(constraint_address):
        return False

    constraint_ints = bytearray(constraint_address)
    mask_ints = bytearray(mask)
    address_ints = bytearray(address)
    for index in range(len(address_ints)):
        if address_ints[index] & mask_ints[index] != \
                constraint_ints[index] & mask_ints[index]:
            return False
    return True


def _directory_name_match(constraint, name):
    """
    Checks if a directory name satisfies a directoryName constraint. The
    constraint's RDN sequence must be a prefix of the name's RDN sequence,
    with RDNs compared as defined by RFC 5280, Section 7.1.

    :param constraint:
        An x509.Name object of the constraint

    :param name:
        An x509.Name object to check

    :return:
        A boolean
    """

    constraint_rdns = constraint.chosen
    name_rdns = name.chosen
    if len(constraint_rdns) > len(name_rdns):
        return False
    for index, constraint_rdn in enumerate(constraint_rdns):
        if constraint_rdn != name_rdns[index]:
            return False
    return True


def _match_dns_name(base, name):
    return _dns_name_match(base.chosen.native, name.chosen.native)


def _match_rfc822_name(base, name):
    return _rfc822_name_match(base.chosen.native, name.chosen.native)


def _match_ip_address(base, name):
    return _ip_address_match(base.chosen.contents, name.chosen.contents)


def _match_directory_name(base, name):
    return _directory_name_match(base.chosen, name.chosen)


_MATCHERS = {
    'dns_name': _match_dns_name,
    'rfc822_name': _match_rfc822_name,
    'ip_address': _match_ip_address,
    'directory_name': _match_directory_name,
}
