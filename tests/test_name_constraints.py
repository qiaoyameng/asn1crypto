# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from asn1crypto import x509
from asn1crypto.name_constraints import (
    NameConstraintVerdict,
    UnsupportedNameConstraint,
    evaluate_name_constraints,
)

from ._unittest_compat import patch

patch()


def _general_name(name, value):
    return x509.GeneralName(name, value)


def _constraints(permitted=None, excluded=None):
    value = {}
    if permitted is not None:
        value['permitted_subtrees'] = [
            {'base': base} if isinstance(base, x509.GeneralName) else base
            for base in permitted
        ]
    if excluded is not None:
        value['excluded_subtrees'] = [
            {'base': base} if isinstance(base, x509.GeneralName) else base
            for base in excluded
        ]
    return x509.NameConstraints(value)


def _dns(value):
    return _general_name('dns_name', value)


def _email(value):
    return _general_name('rfc822_name', value)


def _ip(value):
    return _general_name('ip_address', value)


def _directory(value):
    return _general_name('directory_name', x509.Name.build(value))


class NameConstraintsTests(unittest.TestCase):

    def test_dns_permitted_basic(self):
        chain = [_constraints(permitted=[_dns('example.com')])]
        verdict = evaluate_name_constraints(chain, _dns('www.example.com'))
        self.assertIsInstance(verdict, NameConstraintVerdict)
        self.assertTrue(verdict)
        self.assertEqual(True, verdict.allowed)
        self.assertEqual(None, verdict.level)

    def test_dns_permitted_apex(self):
        chain = [_constraints(permitted=[_dns('example.com')])]
        self.assertTrue(evaluate_name_constraints(chain, _dns('example.com')))

    def test_dns_label_boundary(self):
        # example.com must not be treated as a suffix of badexample.com
        chain = [_constraints(permitted=[_dns('example.com')])]
        verdict = evaluate_name_constraints(chain, _dns('badexample.com'))
        self.assertFalse(verdict)
        self.assertEqual(0, verdict.level)
        self.assertEqual('permitted', verdict.kind)

    def test_dns_leading_period(self):
        chain = [_constraints(permitted=[_dns('.example.com')])]
        self.assertTrue(
            evaluate_name_constraints(chain, _dns('host.example.com'))
        )
        self.assertTrue(
            evaluate_name_constraints(chain, _dns('my.host.example.com'))
        )
        # A leading period excludes the apex name itself
        verdict = evaluate_name_constraints(chain, _dns('example.com'))
        self.assertFalse(verdict)
        self.assertEqual(0, verdict.level)
        self.assertEqual('permitted', verdict.kind)

    def test_dns_case_insensitive(self):
        chain = [_constraints(permitted=[_dns('Example.COM')])]
        self.assertTrue(evaluate_name_constraints(chain, _dns('WWW.EXAMPLE.COM')))

    def test_dns_two_level_intersection(self):
        # Permitted subtrees narrow level-by-level
        chain = [
            _constraints(permitted=[_dns('example.com')]),
            _constraints(permitted=[_dns('sub.example.com')]),
        ]
        self.assertTrue(
            evaluate_name_constraints(chain, _dns('www.sub.example.com'))
        )
        # The second level is the one that actually takes effect here
        verdict = evaluate_name_constraints(chain, _dns('other.example.com'))
        self.assertFalse(verdict)
        self.assertEqual(1, verdict.level)
        self.assertEqual('permitted', verdict.kind)
        self.assertEqual(1, len(verdict.subtrees))
        self.assertEqual(
            'sub.example.com',
            verdict.subtrees[0]['base'].native,
        )

    def test_dns_excluded_accumulates(self):
        chain = [
            _constraints(permitted=[_dns('example.com')]),
            _constraints(excluded=[_dns('bad.example.com')]),
        ]
        verdict = evaluate_name_constraints(chain, _dns('www.bad.example.com'))
        self.assertFalse(verdict)
        self.assertEqual(1, verdict.level)
        self.assertEqual('excluded', verdict.kind)
        self.assertEqual('bad.example.com', verdict.subtree['base'].native)

    def test_dns_excluded_at_earlier_level(self):
        chain = [
            _constraints(excluded=[_dns('bad.example.com')]),
            _constraints(permitted=[_dns('bad.example.com')]),
        ]
        verdict = evaluate_name_constraints(chain, _dns('bad.example.com'))
        self.assertFalse(verdict)
        self.assertEqual(0, verdict.level)
        self.assertEqual('excluded', verdict.kind)

    def test_dns_unconstrained_form(self):
        # Permitted subtrees of another name form do not constrain dNSName
        chain = [_constraints(permitted=[_email('example.com')])]
        self.assertTrue(evaluate_name_constraints(chain, _dns('anything.org')))

    def test_email_host(self):
        chain = [_constraints(permitted=[_email('example.com')])]
        self.assertTrue(evaluate_name_constraints(chain, _email('user@example.com')))
        verdict = evaluate_name_constraints(chain, _email('user@sub.example.com'))
        self.assertFalse(verdict)
        self.assertEqual('permitted', verdict.kind)
        verdict = evaluate_name_constraints(chain, _email('user@badexample.com'))
        self.assertFalse(verdict)

    def test_email_domain(self):
        chain = [_constraints(permitted=[_email('.example.com')])]
        self.assertTrue(
            evaluate_name_constraints(chain, _email('user@mail.example.com'))
        )
        verdict = evaluate_name_constraints(chain, _email('user@example.com'))
        self.assertFalse(verdict)
        self.assertEqual('permitted', verdict.kind)

    def test_email_complete_address(self):
        # A complete address constrains a single mailbox
        chain = [_constraints(permitted=[_email('root@example.com')])]
        self.assertTrue(
            evaluate_name_constraints(chain, _email('root@example.com'))
        )
        verdict = evaluate_name_constraints(chain, _email('other@example.com'))
        self.assertFalse(verdict)
        self.assertEqual(0, verdict.level)
        self.assertEqual('permitted', verdict.kind)
        verdict = evaluate_name_constraints(chain, _email('root@sub.example.com'))
        self.assertFalse(verdict)

    def test_email_excluded_complete_address(self):
        chain = [
            _constraints(permitted=[_email('example.com')]),
            _constraints(excluded=[_email('root@example.com')]),
        ]
        verdict = evaluate_name_constraints(chain, _email('root@example.com'))
        self.assertFalse(verdict)
        self.assertEqual(1, verdict.level)
        self.assertEqual('excluded', verdict.kind)
        self.assertEqual('root@example.com', verdict.subtree['base'].native)
        self.assertTrue(evaluate_name_constraints(chain, _email('user@example.com')))

    def test_ip_v4(self):
        chain = [_constraints(permitted=[_ip('192.0.2.0/24')])]
        self.assertTrue(evaluate_name_constraints(chain, _ip('192.0.2.7')))
        verdict = evaluate_name_constraints(chain, _ip('192.0.3.1'))
        self.assertFalse(verdict)
        self.assertEqual('permitted', verdict.kind)

    def test_ip_v6(self):
        chain = [_constraints(permitted=[_ip('2001:db8::/32')])]
        self.assertTrue(evaluate_name_constraints(chain, _ip('2001:db8::1')))
        verdict = evaluate_name_constraints(chain, _ip('2001:db9::1'))
        self.assertFalse(verdict)

    def test_ip_family_mismatch(self):
        chain = [_constraints(permitted=[_ip('192.0.2.0/24')])]
        verdict = evaluate_name_constraints(chain, _ip('2001:db8::1'))
        self.assertFalse(verdict)
        self.assertEqual('permitted', verdict.kind)

    def test_ip_excluded(self):
        chain = [
            _constraints(permitted=[_ip('192.0.2.0/24')]),
            _constraints(excluded=[_ip('192.0.2.128/25')]),
        ]
        self.assertTrue(evaluate_name_constraints(chain, _ip('192.0.2.1')))
        verdict = evaluate_name_constraints(chain, _ip('192.0.2.200'))
        self.assertFalse(verdict)
        self.assertEqual(1, verdict.level)
        self.assertEqual('excluded', verdict.kind)

    def test_ip_non_contiguous_mask(self):
        # 10.0.0.0 with a mask of 255.0.255.0 is not supported
        constraint = _general_name(
            'ip_address',
            x509.IPAddress.load(b'\x04\x08\x0a\x00\x00\x00\xff\x00\xff\x00'),
        )
        chain = [_constraints(excluded=[constraint])]
        with self.assertRaises(UnsupportedNameConstraint):
            evaluate_name_constraints(chain, _ip('10.0.0.1'))

    def test_ip_invalid_length(self):
        constraint = _general_name(
            'ip_address',
            x509.IPAddress.load(b'\x04\x05\x0a\x00\x00\x00\xff'),
        )
        chain = [_constraints(permitted=[constraint])]
        with self.assertRaises(UnsupportedNameConstraint):
            evaluate_name_constraints(chain, _ip('10.0.0.1'))

    def test_directory_name_prefix(self):
        chain = [
            _constraints(permitted=[
                _directory({'country_name': 'US', 'organization_name': 'Example LLC'}),
            ]),
        ]
        name = _directory({
            'country_name': 'US',
            'organization_name': 'Example LLC',
            'common_name': 'host.example.com',
        })
        self.assertTrue(evaluate_name_constraints(chain, name))

    def test_directory_name_not_within(self):
        chain = [
            _constraints(permitted=[
                _directory({'country_name': 'US', 'organization_name': 'Example LLC'}),
            ]),
        ]
        name = _directory({'country_name': 'US', 'organization_name': 'Other LLC'})
        verdict = evaluate_name_constraints(chain, name)
        self.assertFalse(verdict)
        self.assertEqual(0, verdict.level)
        self.assertEqual('permitted', verdict.kind)

    def test_directory_name_case_insensitive_rdn(self):
        chain = [
            _constraints(permitted=[
                _directory({'country_name': 'us', 'organization_name': 'example llc'}),
            ]),
        ]
        name = _directory({'country_name': 'US', 'organization_name': 'Example LLC'})
        self.assertTrue(evaluate_name_constraints(chain, name))

    def test_directory_name_excluded(self):
        chain = [
            _constraints(permitted=[_directory({'country_name': 'US'})]),
            _constraints(excluded=[
                _directory({'country_name': 'US', 'organization_name': 'Bad LLC'}),
            ]),
        ]
        name = _directory({'country_name': 'US', 'organization_name': 'Bad LLC'})
        verdict = evaluate_name_constraints(chain, name)
        self.assertFalse(verdict)
        self.assertEqual(1, verdict.level)
        self.assertEqual('excluded', verdict.kind)

    def test_minimum_not_supported(self):
        chain = [
            _constraints(permitted=[
                {'base': _dns('example.com'), 'minimum': 1},
            ]),
        ]
        with self.assertRaises(UnsupportedNameConstraint):
            evaluate_name_constraints(chain, _dns('www.example.com'))

    def test_maximum_not_supported(self):
        chain = [
            _constraints(excluded=[
                {'base': _dns('example.com'), 'maximum': 0},
            ]),
        ]
        with self.assertRaises(UnsupportedNameConstraint):
            evaluate_name_constraints(chain, _dns('www.example.com'))

    def test_unsupported_name_form(self):
        chain = [_constraints(permitted=[_dns('example.com')])]
        name = _general_name('uniform_resource_identifier', 'http://example.com/')
        with self.assertRaises(UnsupportedNameConstraint):
            evaluate_name_constraints(chain, name)

    def test_none_entries_and_empty_chain(self):
        self.assertTrue(evaluate_name_constraints([], _dns('example.com')))
        self.assertTrue(
            evaluate_name_constraints([None, None], _dns('example.com'))
        )
        chain = [None, _constraints(permitted=[_dns('example.com')])]
        verdict = evaluate_name_constraints(chain, _dns('other.org'))
        self.assertFalse(verdict)
        self.assertEqual(1, verdict.level)

    def test_invalid_name_type(self):
        with self.assertRaises(TypeError):
            evaluate_name_constraints([], 'example.com')

    def test_invalid_chain_entry_type(self):
        with self.assertRaises(TypeError):
            evaluate_name_constraints(['nope'], _dns('example.com'))
