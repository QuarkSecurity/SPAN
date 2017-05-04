# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2017 Karl MacMillan
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
import logging
import re

from setools import mixins, query, TypeAttributeQuery, TypeQuery
from setools.descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from setools.policyrep import IoctlSet, TERuletype
from setools.policyrep.typeattr import Type, BaseType
from setools.policyrep.exception import RuleUseError, RuleNotConditional
from setools.util import match_regex, match_indirect_regex, match_regex_or_set

class TERuleIndex(object):
    def __init__(self):
        self.by_source = {}
        self.by_target = {}
        # I really don't trust the hashing of rules for the sets, so I'm just going to keep
        # a completely separate list of rules and use indexes in this list as the entries in the
        # set.
        self.rules = []

    def __add_to_index(self, index, tname, rule_index):
        if not tname in index:
            index[tname] = set()
        index[tname].add(rule_index)

    def add_rule(self, rule, rule_index):
        self.__add_to_index(self.by_source, rule.source, rule_index)
        self.__add_to_index(self.by_target, rule.target, rule_index)

    def build_index(self, policy):
        for rule in policy.terules():
            self.rules.append(rule)
            rule_index = len(self.rules) - 1
            self.add_rule(rule, rule_index)

    def __get_by_type_name(self, index, ts):
        out = set()
        if ts:
            for t in ts:
                if not t in index:
                    continue
                out = out | index[t]

        return out

    def get_by_type_names(self, sources=None, targets=None):
        sri = self.__get_by_type_name(self.by_source, sources)
        tri = self.__get_by_type_name(self.by_target, targets)

        if sources and targets:
            indexes = sri & tri
        elif sources:
            indexes = sri
        else:
            indexes = tri

        return [self.rules[i] for i in indexes]

def build_index_if_needed(policy):
    if hasattr(policy, "_terule_index"):
        return

    policy._terule_index = TERuleIndex()
    policy._terule_index.build_index(policy)

def get_type_names(policy, tname, is_regex, indirect):
    # Looks like we have to match types and attributes separately
    types = set()
    attributes = set()
    if isinstance(tname, str) or isinstance(tname, BaseType):
        tname = [tname]
    for name in tname:
        types.update(TypeQuery(policy, name=name, name_regex=is_regex).results())
        attributes.update(TypeAttributeQuery(policy, name=name, name_regex=is_regex).results())

    out = set()
    start = types | attributes
    for x in start:
        out.add(str(x))
        if indirect:
            if isinstance(x, Type):
                [out.add(str(y)) for y in x.attributes()]
            else:
                [out.add(str(y)) for y in x.expand()]

    return out

class CriteriaSetOrValueDescriptor(CriteriaDescriptor):
    def __init__(self, name_regex=None, lookup_function=None, default_value=None, enum_class=None,
                 value_types=(str)):
        super().__init__(name_regex, lookup_function, default_value, enum_class)
        # We use this to determine whether the value passed in is a single value - it's better
        # to check for the value types so that we can accept any iterable easily.
        self.value_types = value_types

    # This lets us accept either a single name or a set of names for source and
    # target type.
    def __set__(self, obj, value):
        if not value:
            self.instances[obj] = None
        elif self.regex and getattr(obj, self.regex, False):
            self.instances[obj] = re.compile(value)
        elif self.lookup_function:
            lookup = getattr(obj.policy, self.lookup_function)
            if isinstance(value, self.value_types):
                self.instances[obj] = lookup(value)
            else:
                self.instances[obj] = set(lookup(v) for v in value)
        elif self.enum_class:
            self.instances[obj] = set(self.enum_class.lookup(v) for v in value)
        else:
            self.instances[obj] = set(value)


class TERuleQueryIndexed(mixins.MatchObjClass, mixins.MatchPermission, query.PolicyQuery):

    """
    Query the Type Enforcement rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype          The list of rule type(s) to match.
    source            The name of the source type/attribute to match.
    source_indirect   If true, members of an attribute will be
                      matched rather than the attribute itself.
                      Default is true.
    source_regex      If true, regular expression matching will
                      be used on the source type/attribute.
                      Obeys the source_indirect option.
                      Default is false.
    target            The name of the target type/attribute to match.
    target_indirect   If true, members of an attribute will be
                      matched rather than the attribute itself.
                      Default is true.
    target_regex      If true, regular expression matching will
                      be used on the target type/attribute.
                      Obeys target_indirect option.
                      Default is false.
    tclass            The object class(es) to match.
    tclass_regex      If true, use a regular expression for
                      matching the rule's object class.
                      Default is false.
    perms             The set of permission(s) to match.
    perms_equal       If true, the permission set of the rule
                      must exactly match the permissions
                      criteria.  If false, any set intersection
                      will match.
                      Default is false.
    perms_regex       If true, regular expression matching will be used
                      on the permission names instead of set logic.
                      Default is false.
    perms_subset      If true, the rule matches if the permissions criteria
                      is a subset of the rule's permission set.
                      Default is false.
    default           The name of the default type to match.
    default_regex     If true, regular expression matching will be
                      used on the default type.
                      Default is false.
    boolean           The set of boolean(s) to match.
    boolean_regex     If true, regular expression matching will be
                      used on the booleans.
                      Default is false.
    boolean_equal     If true, the booleans in the conditional
                      expression of the rule must exactly match the
                      criteria.  If false, any set intersection
                      will match.  Default is false.
    """

    ruletype = CriteriaSetOrValueDescriptor(enum_class=TERuletype)
    source = CriteriaSetOrValueDescriptor("source_regex", "lookup_type_or_attr",
                                          value_types=(str, BaseType))
    source_regex = False
    source_indirect = True
    target = CriteriaSetOrValueDescriptor("target_regex", "lookup_type_or_attr",
                                          value_types=(str, BaseType))
    target_regex = False
    target_indirect = True
    default = CriteriaDescriptor("default_regex", "lookup_type_or_attr")
    default_regex = False
    boolean = CriteriaSetDescriptor("boolean_regex", "lookup_boolean")
    boolean_regex = False
    boolean_equal = False
    _xperms = None
    xperms_equal = False

    @property
    def xperms(self):
        return self._xperms

    @xperms.setter
    def xperms(self, value):
        if value:
            pending_xperms = IoctlSet()

            for low, high in value:
                if not (0 <= low <= 0xffff):
                    raise ValueError("{0:#07x} is not a valid ioctl.".format(low))

                if not (0 <= high <= 0xffff):
                    raise ValueError("{0:#07x} is not a valid ioctl.".format(high))

                if high < low:
                    high, low = low, high

                pending_xperms.update(i for i in range(low, high+1))

            self._xperms = pending_xperms
        else:
            self._xperms = None

    def __init__(self, policy, **kwargs):
        super(TERuleQueryIndexed, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)


    def results(self):
        """Generator which yields all matching TE rules."""
        self.log.info("Generating TE rule results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self._match_object_class_debug(self.log)
        self._match_perms_debug(self.log)
        self.log.debug("Xperms: {0.xperms!r}, eq: {0.xperms_equal}".format(self))
        self.log.debug("Default: {0.default!r}, regex: {0.default_regex}".format(self))
        self.log.debug("Boolean: {0.boolean!r}, eq: {0.boolean_equal}, "
                       "regex: {0.boolean_regex}".format(self))

        build_index_if_needed(self.policy)

        if self.source or self.target:
            stypes = None
            ttypes = None
            if self.source:
                stypes = get_type_names(self.policy, self.source, self.source_regex, self.source_indirect)
            if self.target:
                ttypes = get_type_names(self.policy, self.target, self.target_regex, self.target_indirect)

            rules = self.policy._terule_index.get_by_type_names(sources=stypes, targets=ttypes)
        else:
            rules = self.policy.terules()

        for rule in rules:
            if self.match_rule(rule):
                yield rule


    def match_rule(self, rule):
        #
        # Matching on rule type
        #
        if self.ruletype:
            if rule.ruletype not in self.ruletype:
                return False

        #
        # Matching on object class
        #
        if not self._match_object_class(rule):
            return False

        #
        # Matching on permission set
        #
        try:
            if self.perms and rule.extended:
                if self.perms_equal and len(self.perms) > 1:
                    # if criteria is more than one standard permission,
                    # extended perm rules can never match if the
                    # permission set equality option is on.
                    return False

                if rule.xperm_type not in self.perms:
                    return False
            elif not self._match_perms(rule):
                return False
        except RuleUseError:
            return False

        #
        # Matching on extended permissions
        #
        try:
            if self.xperms and not match_regex_or_set(
                    rule.perms,
                    self.xperms,
                    self.xperms_equal,
                    False):
                return False

        except RuleUseError:
            return False

        #
        # Matching on default type
        #
        if self.default:
            try:
                # because default type is always a single
                # type, hard-code indirect to True
                # so the criteria can be an attribute
                if not match_indirect_regex(
                        rule.default,
                        self.default,
                        True,
                        self.default_regex):
                    return False
            except RuleUseError:
                return False

        #
        # Match on Boolean in conditional expression
        #
        if self.boolean:
            try:
                if not match_regex_or_set(
                        rule.conditional.booleans,
                        self.boolean,
                        self.boolean_equal,
                        self.boolean_regex):
                    return False
            except RuleNotConditional:
                return False

        # if we get here, we have matched all available criteria
        return True