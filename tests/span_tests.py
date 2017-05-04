#
# SENotebook Test Cases
#

import unittest

from .test_context import span as se

from setools.policyrep.typeattr import Type, TypeAttribute

class SENoteBookTests(unittest.TestCase):
    def setUp(self):
        self.p = se.load_policy("../examples/fedora-25-policy.30")
        self.bp = se.load_policy("../examples/fedora-24-policy.30")

    def test_domain_types(self):
        self.assertEqual(len(self.p.domain_types()), 820)
        self.assertEqual(len(self.p.domain_types(["passwd_t", "shadow_t"])), 1)

    def test_custom_types(self):
        custom_types, custom_domains = self.p.new_types(self.bp)

        self.assertEqual(len(custom_types), 34)
        self.assertEqual(len(custom_domains), 5)

    def test_lookup_types(self):
        types = self.p.lookup_type_or_attrs(set(["passwd_t", "domain"]))

        for t in types:
            if t == "passwd_t":
                self.assertIsInstance(t, Type)
            else:
                self.assertIsInstance(t, TypeAttribute)


    def test_types_summary(self):
        custom_types, custom_domains = self.p.new_types(self.bp)

        ts = self.p.types_summary(custom_types)
        self.assertIsNotNone(ts)

    def test_terules_query(self):
        passwd_t = self.p.lookup_type("passwd_t")
        self.assertEqual(len(self.p.terules_query_raw(source=passwd_t)), 671)

        # Test passing in strings or type objects
        str_rules = self.p.terules_query_raw(target=["console_device_t", "tty_device_t"])
        console = self.p.lookup_type("console_device_t")
        tty = self.p.lookup_type("tty_device_t")
        type_rules = self.p.terules_query_raw(target=[console, tty])

        self.assertEqual(len(str_rules), len(type_rules))

        # Make certain we get the same results for single or multiples. This is certainly not
        # a perfect test, but it's too hard to do a rule by rule comparison
        console_domains = {x.source for x in self.p.terules_query_raw(target="console_device_t")}
        tty_domains = {x.source for x in self.p.terules_query_raw(target="tty_device_t")}

        both_domains = {x.source for x in type_rules}

        self.assertEqual(both_domains == (tty_domains | console_domains), True)

        # Just some basic tests that attributes and source works
        a = len(self.p.terules_query_raw(source="domain"))
        b = len(self.p.terules_query_raw(source=["domain"]))
        c = len(self.p.terules_query_raw(source=self.p.lookup_type_or_attr("domain")))
        self.assertEqual(a, b, c)

    def test_load_policies_from_config(self):
        p, ps, bp, bs = se.load_policies_from_config("policy_paths.config")

        self.assertIsNotNone(p)
        self.assertIsNotNone(ps)
        self.assertIsNotNone(bp)
        self.assertIsNotNone(bs)

    def test_constraint_diff(self):
        p, ps, bp, bs = se.load_policies_from_config("policy_paths.config")
        self.assertIsNotNone(bs.diff_mls_constraints(ps))
        self.assertIsNotNone(bs.diff_mcs_constraints(ps))
        self.assertIsNotNone(bs.diff_constraints(ps))

    def test_object_info_flow(self):
        p = se.load_policy("minimal_policy.conf")

        d = p.object_info_flow(object_type="fileb", tclass=["file"], direction="w")
        domains = ["domainb", "domaina", "domaina"]
        conditionals = ["None", "other_bool", "some_bool"]
        for r in d.itertuples():
            self.assertEqual(r.type, domains[r[0]])
            self.assertEqual(str(r.conditional), conditionals[r[0]])

        d = p.object_info_flow(object_type="filea", tclass=["file"], direction="r")
        domains = ["sys_domain"]
        conditionals = ["None"]
        for r in d.itertuples():
            self.assertEqual(r.type, domains[r[0]])
            self.assertEqual(str(r.conditional), conditionals[r[0]])

        d = p.object_info_flow(object_type="filea", tclass=["file"], direction="r", expand_attrs=True)
        domains = ["domaina", "domainc", "domaina", "domainc"]
        conditionals = ["None", "None", "some_bool", "some_bool"]
        for r in d.itertuples():
            self.assertEqual(r.type, domains[r[0]])
            self.assertEqual(str(r.conditional), conditionals[r[0]])


    def test_domain_info_flow(self):
        p = se.load_policy("minimal_policy.conf")

        d = p.domain_info_flow(domain="domaina", tclass=["file"], direction="w")
        files = ["fileb", "fileb"]
        conditionals = ["other_bool", "some_bool"]
        for r in d.itertuples():
            self.assertEqual(r.type, files[r[0]])
            self.assertEqual(str(r.conditional), conditionals[r[0]])

        d = p.domain_info_flow(domain="domaina", tclass=["file"], direction="r")
        files = ["filea"]
        conditionals = ["None"]
        for r in d.itertuples():
            self.assertEqual(r.type, files[r[0]])
            self.assertEqual(str(r.conditional), conditionals[r[0]])

        d = p.domain_info_flow(domain="domainb", tclass=["file"], direction="w")
        files = ["fileb"]
        conditionals = ["None"]
        for r in d.itertuples():
            self.assertEqual(r.type, files[r[0]])
            self.assertEqual(str(r.conditional), conditionals[r[0]])

    def test_domains_that_can_relabel(self):
        p = se.load_policy("minimal_policy.conf")

        d = p.domains_that_can_relabel("relabel_from", "relabel_to")
        domains = ["diff_cond_relabel_domain", "partial_relabel_domain", "partial_relabel_domainb", "relabel_domain", "same_cond_relabel_domain"]
        conds = [("some_bool", "other_bool"), ("some_bool", "None"), ("None", "other_bool"), ("None", "None"), ("some_bool", "some_bool")]
        for r in d.itertuples():
            self.assertEqual(r.type, domains[r[0]])
            f, t = conds[r[0]]
            self.assertEqual(str(r.from_conditional[0]), f)
            self.assertEqual(str(r.to_conditional[0]), t)






