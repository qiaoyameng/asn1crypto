# coding: utf-8

"""
RFC 5280 name constraint evaluation

This module evaluates the syntax and matching rules from RFC 5280 section
4.2.1.10. It deliberately does not perform any other certificate path
validation.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from . import x509
from .util import int_from_bytes


DNS_NAME = 'dNSName'
RFC822_NAME = 'rfc822Name'
IP_ADDRESS = 'iPAddress'
DIRECTORY_NAME = 'directoryName'

_NAME_FIELD_MAP = {
    'dns_name': DNS_NAME,
    'rfc822_name': RFC822_NAME,
    'ip_address': IP_ADDRESS,
    'directory_name': DIRECTORY_NAME,
}


class NameConstraintsError(ValueError):
    """
    The base class for name constraint evaluation errors.
    """

    pass


class UnsupportedNameConstraint(NameConstraintsError):
    """
    A constraint uses a feature or name form that this evaluator does not
    support.
    """

    def __init__(self, message, level=None, section=None, index=None):
        super(UnsupportedNameConstraint, self).__init__(message)
        self.level = level
        self.section = section
        self.index = index


class InvalidNameConstraint(NameConstraintsError):
    """
    A name constraint is malformed.
    """

    def __init__(self, message, level=None, section=None, index=None):
        super(InvalidNameConstraint, self).__init__(message)
        self.level = level
        self.section = section
        self.index = index


class NameConstraintResult(object):
    """
    The result of evaluating a name against an ordered chain of name
    constraints.

    :var allowed:
        A boolean - if the name matched every permitted subtree and no
        excluded subtree
    :var level:
        None for an allowed name, otherwise the zero-based chain level of the
        effective constraint
    :var section:
        None for an allowed name, otherwise ``"permitted_subtrees"`` or
        ``"excluded_subtrees"``
    :var index:
        None for an allowed name or a failure against permitted subtrees with
        no single offending member; otherwise the zero-based index of the
        offending subtree
    :var name_type:
        The RFC-style name type that was evaluated
    :var name:
        The GeneralName object that was evaluated
    :var constraints:
        None for an allowed name, otherwise the relevant GeneralSubtrees from
        the effective chain level
    :var constraint:
        None unless one excluded subtree matched; otherwise that GeneralSubtree
    """

    def __init__(self, allowed, name_type, name, level=None, section=None,
                 index=None, constraints=None, constraint=None):
        self.allowed = allowed
        self.level = level
        self.section = section
        self.index = index
        self.name_type = name_type
        self.name = name
        self.constraints = constraints
        self.constraint = constraint

    def __bool__(self):
        return self.allowed

    def __nonzero__(self):
        return self.allowed

    def __repr__(self):
        if self.allowed:
            detail = 'allowed'
        else:
            detail = 'denied at level %r, %s' % (self.level, self.section)
            if self.index is not None:
                detail += '[%r]' % self.index
        return '<NameConstraintResult %s>' % detail


def evaluate_name_constraints(name, name_constraints_chain):
    """
    Evaluates one name against name constraints from a certificate chain.

    The constraints must be supplied from trust anchor toward end entity.
    Permitted subtrees are intersected level by level. Excluded subtrees from
    every level accumulate.

    :param name:
        An x509.GeneralName or x509.Name object. A bare x509.Name is treated
        as a directoryName.

    :param name_constraints_chain:
        An iterable of x509.NameConstraints objects, in chain order. A None
        entry represents a certificate with no name constraints extension.

    :return:
        A NameConstraintResult object
    """

    general_name = _as_general_name(name)

    chain = list(name_constraints_chain)
    for level, constraints in enumerate(chain):
        if constraints is None:
            continue

        for section in ('permitted_subtrees', 'excluded_subtrees'):
            subtrees = constraints[section]
            if subtrees.native is None:
                continue
            for index, subtree in enumerate(subtrees):
                _validate_subtree(subtree, level, section, index)

    if general_name.name not in _NAME_FIELD_MAP:
        raise UnsupportedNameConstraint(
            'GeneralName type %s is not supported' % general_name.name
        )

    name_type = _NAME_FIELD_MAP[general_name.name]
    matcher = _MATCHERS[name_type]
    candidate = matcher.parse_name(general_name.chosen)

    for level, constraints in enumerate(chain):
        if constraints is None:
            continue

        permitted = constraints['permitted_subtrees']
        if permitted.native is not None:
            matching_subtree = _find_matching_subtree(
                permitted, candidate, name_type, matcher
            )
            if matching_subtree is None:
                return NameConstraintResult(
                    False, name_type, general_name, level,
                    'permitted_subtrees', None, permitted
                )

        excluded = constraints['excluded_subtrees']
        if excluded.native is not None:
            matching_subtree = _find_matching_subtree(
                excluded, candidate, name_type, matcher
            )
            if matching_subtree is not None:
                index, subtree = matching_subtree
                return NameConstraintResult(
                    False, name_type, general_name, level,
                    'excluded_subtrees', index, excluded, subtree
                )

    return NameConstraintResult(True, name_type, general_name)


check_name_constraints = evaluate_name_constraints


def _as_general_name(name):
    if isinstance(name, x509.Name):
        return x509.GeneralName({'directory_name': name})
    if not isinstance(name, x509.GeneralName):
        raise TypeError(
            'name must be an x509.GeneralName or x509.Name object, not %s'
            % type(name)
        )
    return name


def _validate_subtree(subtree, level, section, index):
    minimum = subtree['minimum'].native
    maximum = subtree['maximum'].native

    if minimum != 0 or maximum is not None:
        raise UnsupportedNameConstraint(
            'Only the default minimum (0) and an absent maximum are supported '
            'at level %r, %s[%r]' % (level, section, index),
            level,
            section,
            index
        )

    base = subtree['base']
    if base.name in _NAME_FIELD_MAP:
        matcher = _MATCHERS[_NAME_FIELD_MAP[base.name]]
        matcher.parse_constraint(base.chosen, level, section, index)


def _find_matching_subtree(subtrees, candidate, name_type, matcher):
    for index, subtree in enumerate(subtrees):
        base = subtree['base']
        if base.name not in _NAME_FIELD_MAP or _NAME_FIELD_MAP[base.name] != name_type:
            continue
        constraint = matcher.parse_constraint(base.chosen)
        if matcher.matches(candidate, constraint):
            return index, subtree
    return None


def _dns_labels(value, location, allow_leading_dot=False):
    raw = value.contents
    if not raw or not isinstance(raw, bytes):
        raise InvalidNameConstraint('Invalid DNS name in %s' % location)

    labels = raw.split(b'.')
    leading_dot = False
    if labels[0] == b'':
        if not allow_leading_dot:
            raise InvalidNameConstraint(
                'DNS name with a leading dot in %s is not permitted' % location
            )
        leading_dot = True
        labels = labels[1:]

    if labels[-1] == b'' or b'' in labels:
        raise InvalidNameConstraint('Invalid DNS name in %s' % location)

    return [label.lower() for label in labels], not leading_dot


def _dns_matches(name, constraint):
    name_labels = name
    constraint_labels, allow_self = constraint

    if len(name_labels) < len(constraint_labels):
        return False
    if len(name_labels) == len(constraint_labels) and not allow_self:
        return False
    return name_labels[-len(constraint_labels):] == constraint_labels


def _parse_dns_name(value):
    labels, _ = _dns_labels(value, 'the checked name')
    return labels


def _parse_dns_constraint(value, level=None, section=None, index=None):
    location = _constraint_location(level, section, index)
    return _dns_labels(value, location, allow_leading_dot=True)


def _email_parts(value, location, allow_domain_constraint=False,
                 allow_leading_dot=False):
    raw = value.contents
    if not raw or not isinstance(raw, bytes):
        raise InvalidNameConstraint('Invalid email address in %s' % location)

    if raw.count(b'@') != 1:
        if allow_domain_constraint and raw.find(b'@') == -1:
            address = None
            domain = raw
        else:
            raise InvalidNameConstraint('Invalid email address in %s' % location)
    else:
        address, domain = raw.rsplit(b'@', 1)
        if not address:
            raise InvalidNameConstraint('Invalid email address in %s' % location)

    labels = domain.split(b'.')
    leading_dot = False
    if labels[0] == b'':
        if not allow_leading_dot or address is not None:
            raise InvalidNameConstraint(
                'Email domain with a leading dot in %s is not permitted' % location
            )
        leading_dot = True
        labels = labels[1:]

    if labels[-1] == b'' or b'' in labels:
        raise InvalidNameConstraint('Invalid email domain in %s' % location)

    if address is None:
        return None, [label.lower() for label in labels], not leading_dot
    return address, [label.lower() for label in labels], True


def _email_matches(name, constraint):
    address, domain = name
    constraint_address, constraint_domain, allow_self = constraint

    if constraint_address is not None:
        return address == constraint_address and domain == constraint_domain

    if len(domain) == len(constraint_domain) and not allow_self:
        return False
    if len(domain) < len(constraint_domain):
        return False
    return domain[-len(constraint_domain):] == constraint_domain


def _parse_email_name(value):
    address, domain, _ = _email_parts(value, 'the checked name')
    return address, domain


def _parse_email_constraint(value, level=None, section=None, index=None):
    location = _constraint_location(level, section, index)
    return _email_parts(
        value,
        location,
        allow_domain_constraint=True,
        allow_leading_dot=True
    )


def _ip_value(value, location, constraint=False):
    raw = value.contents
    if not raw or not isinstance(raw, bytes):
        raise InvalidNameConstraint('Invalid IP address in %s' % location)

    if not constraint and len(raw) == 4:
        address = raw
        mask = b'\xff\xff\xff\xff'
    elif not constraint and len(raw) == 16:
        address = raw
        mask = b'\xff' * 16
    elif constraint and len(raw) == 8:
        address = raw[:4]
        mask = raw[4:]
    elif constraint and len(raw) == 32:
        address = raw[:16]
        mask = raw[16:]
    else:
        raise InvalidNameConstraint('Invalid IP address length in %s' % location)

    return address, mask


def _ip_matches(name, constraint):
    name_address, _ = name
    constraint_address, mask = constraint
    if len(name_address) != len(constraint_address):
        return False

    name_number = int_from_bytes(name_address) & int_from_bytes(mask)
    constraint_number = int_from_bytes(constraint_address) & int_from_bytes(mask)
    return name_number == constraint_number


def _parse_ip_name(value):
    raw = value.contents
    if not raw or not isinstance(raw, bytes) or len(raw) not in (4, 16):
        raise InvalidNameConstraint('Invalid IP address in the checked name')
    return raw, None


def _parse_ip_constraint(value, level=None, section=None, index=None):
    return _ip_value(
        value,
        _constraint_location(level, section, index),
        constraint=True
    )


def _directory_value(value):
    if not isinstance(value, x509.Name):
        raise InvalidNameConstraint('Invalid directoryName')
    return value.chosen


def _directory_matches(name, constraint):
    if len(name) < len(constraint):
        return False
    for index, rdn in enumerate(constraint):
        if name[index] != rdn:
            return False
    return True


def _parse_directory_name(value):
    return _directory_value(value)


def _parse_directory_constraint(value, level=None, section=None, index=None):
    directory = _directory_value(value)
    if len(directory) == 0:
        raise InvalidNameConstraint(
            'Empty directoryName in %s'
            % _constraint_location(level, section, index)
        )
    return directory


def _constraint_location(level, section, index):
    if level is None:
        return 'a name constraint'
    return 'level %r, %s[%r]' % (level, section, index)


class _Matcher(object):
    def __init__(self, parse_name, parse_constraint, matches):
        self.parse_name = parse_name
        self.parse_constraint = parse_constraint
        self.matches = matches


_MATCHERS = {
    DNS_NAME: _Matcher(
        _parse_dns_name,
        _parse_dns_constraint,
        _dns_matches
    ),
    RFC822_NAME: _Matcher(
        _parse_email_name,
        _parse_email_constraint,
        _email_matches
    ),
    IP_ADDRESS: _Matcher(
        _parse_ip_name,
        _parse_ip_constraint,
        _ip_matches
    ),
    DIRECTORY_NAME: _Matcher(
        _parse_directory_name,
        _parse_directory_constraint,
        _directory_matches
    ),
}
