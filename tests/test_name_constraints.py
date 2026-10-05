# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from asn1crypto import name_constraints, x509


class NameConstraintsTests(unittest.TestCase):

    def general_name(self, name_type, value):
        if name_type == 'directoryName':
            chosen = x509.Name.build(value)
        elif name_type == 'dNSName':
            chosen = x509.DNSName(value)
        elif name_type == 'rfc822Name':
            chosen = x509.EmailAddress(value)
        else:
            chosen = self.ip_address(value)
        return x509.GeneralName({self.field_name(name_type): chosen})

    def field_name(self, name_type):
        return {
            'dNSName': 'dns_name',
            'rfc822Name': 'rfc822_name',
            'iPAddress': 'ip_address',
            'directoryName': 'directory_name',
        }[name_type]

    def ip_address(self, contents):
        value = x509.IPAddress()
        value.contents = contents
        return value

    def subtree(self, name_type, value, minimum=0, maximum=None):
        data = {
            'base': self.general_name(name_type, value),
            'minimum': minimum,
        }
        if maximum is not None:
            data['maximum'] = maximum
        return x509.GeneralSubtree(data)

    def constraints(self, permitted=None, excluded=None):
        data = {}
        if permitted is not None:
            data['permitted_subtrees'] = permitted
        if excluded is not None:
            data['excluded_subtrees'] = excluded
        return x509.NameConstraints(data)

    def assertDenied(self, result, level, section, index=None):
        self.assertFalse(result.allowed)
        self.assertEqual(level, result.level)
        self.assertEqual(section, result.section)
        self.assertEqual(index, result.index)

    def test_dns_name_uses_domain_boundary(self):
        constraints = self.constraints(permitted=[
            self.subtree('dNSName', 'example.com')
        ])

        self.assertTrue(name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'example.com'),
            [constraints]
        ).allowed)
        self.assertTrue(name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'www.example.com'),
            [constraints]
        ).allowed)

        result = name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'badexample.com'),
            [constraints]
        )
        self.assertDenied(result, 0, 'permitted_subtrees')

    def test_leading_dot_does_not_permit_constraint_domain_itself(self):
        constraints = self.constraints(permitted=[
            self.subtree('dNSName', '.example.com')
        ])

        result = name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'example.com'),
            [constraints]
        )
        self.assertDenied(result, 0, 'permitted_subtrees')

        self.assertTrue(name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'www.example.com'),
            [constraints]
        ).allowed)

    def test_permitted_subtrees_intersect_at_effective_level(self):
        level0 = self.constraints(permitted=[
            self.subtree('dNSName', 'example.com')
        ])
        level1 = self.constraints(permitted=[
            self.subtree('dNSName', 'www.example.com')
        ])

        allowed = name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'host.www.example.com'),
            [level0, level1]
        )
        self.assertTrue(allowed.allowed)

        denied = name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'mail.example.com'),
            [level0, level1]
        )
        self.assertDenied(denied, 1, 'permitted_subtrees')
        self.assertEqual('dNSName', denied.name_type)

    def test_excluded_subtrees_accumulate(self):
        level0 = self.constraints(
            permitted=[self.subtree('dNSName', 'example.com')],
            excluded=[self.subtree('dNSName', 'bad.example.com')]
        )
        level1 = self.constraints(
            excluded=[self.subtree('dNSName', 'www.example.com')]
        )

        result0 = name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'bad.example.com'),
            [level0, level1]
        )
        self.assertDenied(result0, 0, 'excluded_subtrees', 0)
        self.assertEqual(level0['excluded_subtrees'][0], result0.constraint)
        self.assertEqual(level0['excluded_subtrees'], result0.constraints)

        result1 = name_constraints.evaluate_name_constraints(
            self.general_name('dNSName', 'www.example.com'),
            [level0, level1]
        )
        self.assertDenied(result1, 1, 'excluded_subtrees', 0)
        self.assertEqual(level1['excluded_subtrees'][0], result1.constraint)
        self.assertEqual(level1['excluded_subtrees'], result1.constraints)

    def test_email_constraint_is_not_a_suffix_license(self):
        full_address = self.constraints(permitted=[
            self.subtree('rfc822Name', 'alice@example.com')
        ])

        self.assertTrue(name_constraints.evaluate_name_constraints(
            self.general_name('rfc822Name', 'alice@example.com'),
            [full_address]
        ).allowed)

        for address in ('alice@badexample.com', 'bob@example.com'):
            result = name_constraints.evaluate_name_constraints(
                self.general_name('rfc822Name', address),
                [full_address]
            )
            self.assertDenied(result, 0, 'permitted_subtrees')

    def test_email_domain_constraint_uses_domain_boundary(self):
        constraints = self.constraints(permitted=[
            self.subtree('rfc822Name', 'example.com')
        ])

        self.assertTrue(name_constraints.evaluate_name_constraints(
            self.general_name('rfc822Name', 'alice@mail.example.com'),
            [constraints]
        ).allowed)

        result = name_constraints.evaluate_name_constraints(
            self.general_name('rfc822Name', 'alice@badexample.com'),
            [constraints]
        )
        self.assertDenied(result, 0, 'permitted_subtrees')

    def test_non_contiguous_ip_mask_is_evaluated_as_a_bit_mask(self):
        constraint_bytes = b'\x0a\x00\x02\x00\xff\x00\xff\x00'
        constraints = self.constraints(permitted=[
            self.subtree('iPAddress', constraint_bytes)
        ])

        matching = name_constraints.evaluate_name_constraints(
            self.general_name('iPAddress', b'\x0a\x09\x02\x09'),
            [constraints]
        )
        self.assertTrue(matching.allowed)

        denied = name_constraints.evaluate_name_constraints(
            self.general_name('iPAddress', b'\x0a\x09\x03\x09'),
            [constraints]
        )
        self.assertDenied(denied, 0, 'permitted_subtrees')

    def test_non_contiguous_ip_mask_denial_reports_effective_level(self):
        level0 = self.constraints(permitted=[
            self.subtree('iPAddress', b'\x0a\x00\x00\x00\xff\x00\x00\x00')
        ])
        level1 = self.constraints(permitted=[
            self.subtree('iPAddress', b'\x0a\x00\x02\x00\xff\x00\xff\x00')
        ])

        result = name_constraints.evaluate_name_constraints(
            self.general_name('iPAddress', b'\x0a\x09\x03\x09'),
            [level0, level1]
        )
        self.assertDenied(result, 1, 'permitted_subtrees')
        self.assertEqual(level1['permitted_subtrees'], result.constraints)
        self.assertIsNone(result.constraint)

    def test_bare_name_is_treated_as_directory_name(self):
        constraints = self.constraints(permitted=[
            self.subtree('directoryName', {'common_name': 'Example'})
        ])

        result = name_constraints.evaluate_name_constraints(
            x509.Name.build({'common_name': 'Example'}),
            [constraints]
        )
        self.assertTrue(result.allowed)
        self.assertEqual('directoryName', result.name_type)

    def test_directory_name_matches_rdn_sequence_prefix(self):
        constraint_name = {
            'country_name': 'US',
            'organization_name': 'Example',
        }
        constraints = self.constraints(permitted=[
            self.subtree('directoryName', constraint_name)
        ])

        leaf = self.general_name('directoryName', {
            'country_name': 'US',
            'organization_name': 'Example',
            'common_name': 'Leaf',
        })
        self.assertTrue(name_constraints.evaluate_name_constraints(
            leaf,
            [constraints]
        ).allowed)

        other = self.general_name('directoryName', {
            'country_name': 'US',
            'organization_name': 'Other',
        })
        result = name_constraints.evaluate_name_constraints(other, [constraints])
        self.assertDenied(result, 0, 'permitted_subtrees')

    def test_non_default_minimum_fails_with_level_and_location(self):
        constraints = self.constraints(permitted=[
            self.subtree('dNSName', 'example.com', minimum=1)
        ])

        with self.assertRaises(name_constraints.UnsupportedNameConstraint) as cm:
            name_constraints.evaluate_name_constraints(
                self.general_name('dNSName', 'www.example.com'),
                [None, constraints]
            )

        self.assertEqual(1, cm.exception.level)
        self.assertEqual('permitted_subtrees', cm.exception.section)
        self.assertEqual(0, cm.exception.index)

    def test_non_default_maximum_fails(self):
        constraints = self.constraints(excluded=[
            self.subtree('dNSName', 'example.com', maximum=2)
        ])

        with self.assertRaises(name_constraints.UnsupportedNameConstraint) as cm:
            name_constraints.evaluate_name_constraints(
                self.general_name('dNSName', 'www.example.com'),
                [constraints]
            )

        self.assertEqual(0, cm.exception.level)
        self.assertEqual('excluded_subtrees', cm.exception.section)

    def test_non_default_limits_are_validated_before_name_type(self):
        constraints = self.constraints(permitted=[
            x509.GeneralSubtree({
                'base': x509.GeneralName({
                    'uniform_resource_identifier': x509.URI('https://example.com')
                }),
                'minimum': 1,
            })
        ])
        name = x509.GeneralName({
            'uniform_resource_identifier': x509.URI('https://example.org')
        })

        with self.assertRaises(name_constraints.UnsupportedNameConstraint) as cm:
            name_constraints.evaluate_name_constraints(name, [constraints])

        self.assertEqual(0, cm.exception.level)
        self.assertEqual('permitted_subtrees', cm.exception.section)
        self.assertEqual(0, cm.exception.index)


if __name__ == '__main__':
    unittest.main()
