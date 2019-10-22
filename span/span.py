# Copyright 2017 Quark Security, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# Basic Utilities for Policy Analysis Within Jupyter Notebook
#

import configparser
import os.path
import re

import pandas as pd
import setools as se
from IPython.display import display, Markdown
from setools.policyrep.typeattr import TypeAttribute

from . import indexed_terulequery

pd.options.display.max_rows = 2000
pd.set_option('max_colwidth', 2000)


def dataframe_hide_none(val):
    if val is None or (isinstance(val, set) and len(val) == 0):
        return "color: white"

    return "color: red"


permmap = se.PermissionMap()
# Some common permission sets for use in rule queries
file_w_perms = [x.perm for x in permmap.perms("file") if x.direction == "w"]
file_r_perms = [x.perm for x in permmap.perms("file") if x.direction == "r"]

file_classes = ["file", "blk_file", "chr_file", "lnk_file"]
file_dir_classes = file_classes + ["dir"]

all_object_classes = ['bluetooth_socket', 'netlink_audit_socket', 'tcp_socket', 'msgq', 'rose_socket', 'x_property', 'binder', 'db_procedure', 'dir', 'peer', 'tipc_socket', 'blk_file', 'chr_file', 'db_table', 'db_tuple', 'dbus', 'ipc', 'ipx_socket', 'lnk_file', 'netlink_connector_socket', 'process', 'atmsvc_socket', 'capability2', 'fd', 'nfc_socket', 'packet', 'socket', 'bridge_socket', 'cap_userns', 'fifo_file', 'file', 'node', 'process2', 'x_cursor', 'x_server', 'bpf', 'decnet_socket', 'irda_socket', 'phonet_socket', 'db_view', 'netlink_nflog_socket', 'rds_socket', 'sctp_socket', 'xdp_socket', 'key', 'netlink_netfilter_socket', 'ib_socket', 'netlink_iscsi_socket', 'netlink_tcpdiag_socket', 'unix_stream_socket', 'x_synthetic_event', 'db_database', 'db_language', 'kernel_service', 'netlink_route_socket', 'pppox_socket', 'x_extension', 'db_sequence', 'ieee802154_socket', 'infiniband_endport', 'netlink_rdma_socket', 'netrom_socket', 'shm', 'x_resource', 'llc_socket', 'netlink_selinux_socket', 'capability', 'mpls_socket', 'netlink_ip6fw_socket', 'cap2_userns', 'dccp_socket', 'iucv_socket', 'netlink_firewall_socket', 'sock_file', 'unix_dgram_socket', 'kcm_socket', 'netlink_kobject_uevent_socket', 'vsock_socket', 'db_blob', 'filesystem', 'netlink_xfrm_socket', 'rxrpc_socket', 'x_device', 'can_socket', 'db_schema', 'netlink_dnrt_socket', 'netlink_generic_socket', 'x_client', 'x_gc', 'atmpvc_socket', 'context', 'nscd', 'passwd', 'x_event', 'x_font', 'ax25_socket', 'netlink_scsitransport_socket', 'service', 'x25_socket', 'isdn_socket', 'key_socket', 'netif', 'packet_socket', 'memprotect', 'msg', 'qipcrtr_socket', 'tun_socket', 'udp_socket', 'appletalk_socket', 'netlink_crypto_socket', 'proxy', 'x_colormap', 'x_screen', 'rawip_socket', 'x_application_data', 'association', 'caif_socket', 'x_selection', 'db_column', 'netlink_socket', 'x_drawable', 'infiniband_pkey', 'sem', 'system', 'x_keyboard', 'alg_socket', 'icmp_socket', 'netlink_fib_lookup_socket', 'security', 'smc_socket', 'x_pointer']


def load_policy(fname):
    return Policy(fname)


def _load_policy_from_section(config_section):
    p = None
    ps = None

    if "binary" in config_section:
        p = load_policy(config_section["binary"])
    if "source" in config_section:
        ps = load_refpolicy_source(config_section["source"])

    return p, ps


def load_policies_from_config(config_fname):
    config = configparser.ConfigParser()
    config.read(config_fname)

    p = None
    ps = None
    bp = None
    bs = None

    if config.has_section("Policy"):
        p, ps = _load_policy_from_section(config["Policy"])

    if config.has_section("BasePolicy"):
        bp, bs = _load_policy_from_section(config["BasePolicy"])

    return p, ps, bp, bs


def cond_expr(rule):
    try:
        return rule.conditional
    except Exception as e:
        return None


def type_names(result):
    return [str(x) for x in result]


def filter_types(types, exclude_re):
    r = re.compile(exclude_re)
    return [x for x in types if not r.match(str(x))]


def collect_types(p, raw, expand_attrs=True):
    # This takes a list of type, conditional expression, perms tuples and merges all of the types (removing dups)
    # and expands attributes (if expand_attrs is true).
    #
    # It returns a dictionary of t: perms for the unconditional rules and a dictionary of (t, cond): perms for the
    # conditional rules.
    u = {}
    c = {}

    # We first process the unconditional rules because we are not going to show conditional access if
    # there is also unconditional access
    for t, cond, perms in raw:
        if cond:
            continue

        if expand_attrs:
            keys = list(t.expand())
        else:
            keys = [t]

        for k in keys:
            if k in u:
                u[k] = u[k] | perms
            else:
                u[k] = perms

    for t, cond, perms in raw:
        if not cond or t in u:
            continue

        if expand_attrs:
            keys = [(x, cond) for x in t.expand()]
        else:
            keys = [(t, cond)]

        for k in keys:
            if t in c:
                c[k] = c[k] | perms
            else:
                c[k] = perms

    data = []
    for k in sorted(u.keys()):
        v = u[k]
        data.append({"Type": k, "Conditional": None, "Permissions": sorted(v)})

    for k in sorted(c.keys()):
        t, cond = k
        v = c[k]
        data.append({"Type": t, "Conditional": cond, "Permissions": sorted(v)})

    df = pd.DataFrame(data)[["Type", "Conditional", "Permissions"]]
    df.style.applymap(dataframe_hide_none)

    return df


class Policy(se.SELinuxPolicy):
    # common trusted domain types we can filter out to remove noise
    example_trusted_domain_types = ["kernel_t", "rpm_script_t", "setfiles_t", "setfiles_mac_t", "restorecond_t",
                                    "smbd_t", "mount_t", "files_unconfined_type", "xauth_t", "hostname_t",
                                    "readahead_t", "rpm_t", "nmbd_t", "init_t", "initrc_t", "insmod_t", "mdadm_t",
                                    "devices_unconfined_type", "udev_t", "bootloader_t", "system_cronjob_t"]
    trusted_domain_types = []

    domain_attribute = "domain"

    def terules_query_orig(self, **kwargs):
        if "ruletype" not in kwargs:
            kwargs["ruletype"] = [se.TERuletype.allow]
        results = se.TERuleQuery(self, **kwargs).results()
        filtered_results = [x for x in results if x.source not in self.trusted_domain_types]
        return sorted(filtered_results)

    def terules_query_raw(self, **kwargs):
        if "ruletype" not in kwargs:
            kwargs["ruletype"] = [se.TERuletype.allow]
        results = indexed_terulequery.TERuleQueryIndexed(self, **kwargs).results()

        if "trusted_domain_types" in kwargs:
            td = kwargs["trusted_domain_types"]
        else:
            td = self.trusted_domain_types
        if td is not None:
            filtered_results = [x for x in results if x.source not in td]
        else:
            filtered_results = results
        return sorted(filtered_results)

    BASE_RULE_ATTRS = ["source", "target", "tclass"]
    AVRULE_ATTRS = ["perms"]
    AVRULE_XPERMS_RULE_ATTRS = ["perms", "xperm_type"]
    TYPE_RULE_ATTRS = ["default", "filename"]

    def terules_query(self, **kwargs):
        r = self.terules_query_raw(**kwargs)

        data = []
        extra_indexes = set()
        for rule in r:
            rt = se.TERuletype
            if rule.ruletype in (rt.allow, rt.dontaudit, rt.neverallow, rt.dontaudit):
                attrs = self.AVRULE_ATTRS
            elif rule.ruletype in (rt.allowxperm, rt.neverallowxperm, rt.auditallowxperm, rt.dontauditxperm):
                attrs = self.AVRULE_XPERMS_RULE_ATTRS
            else:
                attrs = self.TYPE_RULE_ATTRS
            extra_indexes.update(attrs)

            row = {}
            for attr in self.BASE_RULE_ATTRS + attrs:
                try:
                    row[attr] = getattr(rule, attr)
                except:
                    row[attr] = None
                    continue
            row["cond"] = cond_expr(rule)

            data.append(row)

        if not len(data):
            return None

        df = pd.DataFrame(data)[self.BASE_RULE_ATTRS + list(extra_indexes) + ["cond"]]
        df.style.applymap(dataframe_hide_none)

        return df

    def constraint_query(self, **kwargs):
        if "ruletype" not in kwargs:
            kwargs["ruletype"] = ["mlsconstrain"]
        results = se.ConstraintQuery(self, **kwargs).results()
        return sorted(results)

    def transrules_query(self, **kwargs):
        if "ruletype" not in kwargs:
            kwargs["ruletype"] = [se.TERuletype.type_transition]

        return self.terules_query(**kwargs)

    def roles_query(self, **kwargs):
        return sorted(se.RoleQuery(self, **kwargs).results())

    def types_in_role(self, role_name):
        return sorted([str(x) for x in self.roles_query(name=role_name)[0].types()])

    def roles_for_type(self, type_name):
        roles = sorted([str(x) for x in self.roles()])
        out = []
        for role in roles:
            rtypes = self.types_in_role(role)
            if type_name in rtypes:
                out.append(role)
        return out

    def roletrans_query(self, **kwargs):
        if "ruletype" not in kwargs:
            kwargs["ruletype"] = [se.RBACRuletype.role_transition, se.RBACRuletype.allow]
        return sorted(se.RBACRuleQuery(self, **kwargs).results())

    def dta_analysis(self, domain, *args, **kwargs):
        return list(se.DomainTransitionAnalysis(self, *args, **kwargs).transitions(domain))

    def types_re(self, s, **kwargs):
        q = se.TypeQuery(self, name_regex=True, **kwargs)
        q.name = s
        return sorted(q.results())

    def lookup_type_or_attrs(self, type_names):
        """
        Convert a list of type/attribute names into a list of types.
        
        :param type_names: An iterable of type names 
        :return: An list of Type and TypeAttribute objects
        """

        return sorted([self.lookup_type_or_attr(x) for x in type_names])

    def expand_attributes(self, tlist):
        expanded = set()
        [expanded.update(x.expand()) for x in tlist]

        return expanded

    def attributes_re(self, s, **kwargs):
        q = se.TypeAttributeQuery(self, name_regex=True, **kwargs)
        q.name = s
        return sorted(q.results())

    def attributes_for_type(self, tname):
        attrs = sorted(self.lookup_type(tname).attributes())
        return attrs

    def types_in_attribute(self, attr):
        return sorted(self.attributes_re("^%s$" % attr)[0].expand())

    def new_types(self, base_policy):
        """
        Determine what types are new in this policy compared to another
        policy.
        :param base_policy: The policy to compare with. 
        :return: Tuple contains (list of new types, list of new domains)
        """
        # We have to do this as strings because the hasing
        # from different policies doesn't work correctly
        p_domains = as_strset(self.types())
        bp_domains = as_strset(base_policy.types())

        custom_types = self.lookup_type_or_attrs(p_domains - bp_domains)
        custom_domains = self.lookup_type_or_attrs(self.domain_types(custom_types))

        return custom_types, custom_domains

    def domain_types(self, types=None):
        out = set()
        if types is None:
            types = self.types()
        for t in types:
            if isinstance(t, str):
                t = self.lookup_type(t)
            if self.domain_attribute in list(t.attributes()):
                out.add(t)
        return out

    def domains_with(self, target_name, tclass=["file", "dir"], perms=file_w_perms, expand_attrs=False):
        raw = [(x.source, cond_expr(x), x.perms) for x in
               self.terules_query_raw(target=target_name, tclass=tclass, perms=perms, trusted_domain_types=[])]
        return collect_types(self, raw, expand_attrs=expand_attrs)

    def domains_with_file_w_perms(self, target_name, expand_attrs=False):
        return self.domains_with(self, target_name, tclass=["file", "dir"], perms=file_w_perms,
                                 expand_attrs=expand_attrs)

    def domains_with_file_r_perms(self, target_name, expand_attrs=False):
        return self.domains_with(self, target_name, tclass=["file", "dir"], perms=file_r_perms,
                                 expand_attrs=expand_attrs)

    def domains_that_can_relabel(self, from_type, to_type, expand_attrs=False):
        f = self.domains_with(from_type, tclass=None, perms=["relabelfrom"], expand_attrs=expand_attrs)
        t = self.domains_with(to_type, tclass=None, perms=["relabelto"], expand_attrs=expand_attrs)

        def build_sets(result):
            unconditional = set()
            conditional = {}
            for row in result.itertuples():
                if row[2] is "":
                    unconditional.add(row.type)
                else:
                    if row.type not in conditional:
                        conditional[row.type] = []
                    conditional[row.type].append(row.conditional)

            return unconditional, conditional

        f_u, f_c = build_sets(f)
        t_u, t_c = build_sets(t)

        data = []

        def append_row(d, from_conditional=None, to_conditional=None):
            data.append({"type": d, "from_conditional": from_conditional, "to_conditional": to_conditional})

        # For unconditional rules everything is easy - we just need to which types
        # are in both sets (meaning they both have relabel rules
        for d in sorted(t_u | f_u):
            append_row(d)

        # Conditional rules are harder. We have to look for any matching rules that are conditional
        # or unconditional. And we don't want to merge all of the different conditionals together.
        # So we will have duplicate rows in some cases (which makes it clear in the results which conditionals
        # must be active to allow the relabeling).
        #
        # Since we are looking for pairs and we show _all_ of the conditional relabels we only have to go through
        # the from (or the to) for the conditional rules. Because any domains that we don't hit by going through one
        # by definition don't have a matching pair in the other. BUT the to rules might have a match in the unconditional
        # rules. So we will go through t_c just to match unconditional.
        for d in sorted(f_c.keys()):
            # if we have a match
            if d in t_u:
                append_row(d, from_conditional=f_c[d])
            if d in t_c:
                append_row(d, from_conditional=f_c[d], to_conditional=t_c[d])

        for d in sorted(t_c.keys()):
            if d in f_u:
                append_row(d, to_conditional=t_c[d])

        df = pd.DataFrame(data)[["type", "from_conditional", "to_conditional"]]
        df.style.applymap(dataframe_hide_none)

        return df

    DIR_WRITE = "w"
    DIR_READ = "r"

    def info_flow_perms(self, tclass=["file"], direction=DIR_WRITE, min_weight=7):
        perms = set()
        for c in tclass:
            perms.update([x.perm for x in permmap.perms(c) if
                          (x.direction == direction or x.direction == "b") and x.weight >= min_weight])

        return list(perms)

    def domain_info_flow(self, domain, tclass=file_classes, direction=DIR_WRITE, min_weight=10, expand_attrs=False):
        """
        Return the set of object types that information can flow into or out of for a given domain.
    
        domain - name of the domain type
        tclass - list of target class names
        direction - DIR_WRITE or DIR_READ
        """
        perms = self.info_flow_perms(tclass, direction, min_weight)

        raw = [(x.target, cond_expr(x), as_strset(x.perms)) for x in
               self.terules_query_raw(source=domain, tclass=tclass, perms=perms, trusted_domain_types=[])]

        return collect_types(self, raw, expand_attrs)

    def object_info_flow(self, object_type, tclass=file_classes, direction=DIR_WRITE, min_weight=10,
                         expand_attrs=False):
        """
        Return the set of domain types that information can flow into or out of for a given object.
    
        object_type - name of the object type
        tclass - list of target class names
        direction - DIR_WRITE or DIR_READ
        """
        perms = self.info_flow_perms(tclass, direction, min_weight)

        raw = [(x.source, cond_expr(x), as_strset(x.perms)) for x in
               self.terules_query_raw(target=object_type, tclass=tclass, perms=perms, trusted_domain_types=[])]

        return collect_types(self, raw, expand_attrs)

    def policy_caps(self, **kwargs):
        return list(se.PolCapQuery(self, **kwargs).results())

    def types_summary(self, types):
        data = []
        for t in sorted(types):
            data.append({"name": str(t), "attributes": sorted(t.attributes())})

        df = pd.DataFrame(data)[["name", "attributes"]]
        df.style.applymap(dataframe_hide_none)

        return df

    def domain_summary(self, domain):
        pp_markdown(domain_summary_raw(self, domain))

    def file_summary(self, file_type):
        obj_classes_except_process = as_str(self.classes())
        obj_classes_except_process.remove("process")
        data = {
            "file_type": file_type,
            "attributes": markdown_list(self.attributes_for_type(file_type)),
            "other_trans": markdown_code_from_results(
                self.transrules_query(target=file_type, target_indirect=False, tclass=obj_classes_except_process)),
            "fread": markdown_code_from_results(
                self.terules_query_raw(target=file_type, tclass=file_dir_classes, perms=["read"], target_indirect=False)),
            "fwrite": markdown_code_from_results(
                self.terules_query_raw(target=file_type, tclass=file_dir_classes, perms=["write", "append"],
                                       target_indirect=False)),
        }

        pp_markdown(file_summary_template.format(**data))

    def packet_summary(self, packet_type):
        obj_classes_except_process = as_str(self.classes())
        obj_classes_except_process.remove("process")
        data = {
            "packet_type": packet_type,
            "attributes": markdown_list(self.attributes_for_type(packet_type)),
            "packet": markdown_code_from_results(
                self.terules_query_raw(target=packet_type, tclass=["packet"], target_indirect=False)),
        }

        pp_markdown(packet_summary_template.format(**data))

    def attribute_summary(self, attribute):
        # Attributes are tricky because we do not know if an attribute is really meant for files or for domains
        #  We are going to take some educated guesses with this that may or may not work out well
        #  If we find the word file in the attribute name we treat it as a file
        #  Anything else we're going to great as a domain

        r_file = re.compile(".*file.*")
        obj_classes_except_process = as_str(self.classes())
        obj_classes_except_process.remove("process")

        if r_file.match(attribute):
            data = {
                "file_type": attribute,
                "types": markdown_list(self.types_in_attribute(attribute)),
                "other_trans": markdown_code_from_results(
                    self.transrules_query(target=attribute, target_indirect=False, tclass=obj_classes_except_process)),
                "fread": markdown_code_from_results(
                    self.terules_query_raw(target=attribute, tclass=file_dir_classes, perms=["read"],
                                           target_indirect=False)),
                "fwrite": markdown_code_from_results(
                    self.terules_query_raw(target=attribute, tclass=file_dir_classes, perms=["write", "append"],
                                           target_indirect=False)),
            }

            pp_markdown(file_attribute_summary_template.format(**data))

        else:
            data = {
                "attribute": attribute,
                "types": markdown_list(self.types_in_attribute(attribute)),
                "capabilities": markdown_code_from_results(
                    self.terules_query_raw(source=attribute, tclass=["capability"], source_indirect=False)),
                "fread": markdown_code_from_results(
                    self.terules_query_raw(source=attribute, tclass=file_dir_classes, perms=["read"],
                                           source_indirect=False)),
                "fwrite": markdown_code_from_results(
                    self.terules_query_raw(source=attribute, tclass=file_dir_classes, perms=["write", "append"],
                                           source_indirect=False)),
                "packet": markdown_code_from_results(
                    self.terules_query_raw(source=attribute, tclass=["packet"], source_indirect=False)),
                "process": markdown_code_from_results(
                    self.terules_query_raw(source=attribute, tclass=["process"], source_indirect=False)),
                "socket": markdown_code_from_results(
                    self.terules_query_raw(source=attribute, tclass="socket", tclass_regex=True, source_indirect=False))
            }

            pp_markdown(domain_attribute_summary_template.format(**data))


def pp_markdown(markdown):
    display(Markdown(markdown))


def as_str(l):
    return [str(x) for x in l]


def as_strset(l):
    return set(as_str(l))


def markdown_code_from_results(results):
    out = """
```
%s
```
        """ % "\n".join(as_str(results))
    return out


def markdown_list(l):
    out = ""
    for item in as_str(l):
        out = out + "  * `%s`\n" % item

    return out


domain_summary_template = """
### Domain Summary: {domain}

####  Type Attributes

{attributes}

#### Domain Transitions In

{dta_in}

#### Domain Transitions Out

{dta_out}

#### Entrypoints

{entrypoints}

#### Non-Process Transitions

{other_trans}

#### Roles

{roles}

#### Capability Permissions

{capabilities}

#### File Read Permissions

{fread}

#### File Write Permissions

{fwrite}

#### Packet Permissions

{packet}

#### Process Permissions

{process}

#### Socket Permissions

{socket}


"""


def domain_summary_raw(p, domain):
    obj_classes_except_process = as_str(p.classes())
    obj_classes_except_process.remove("process")
    data = {
        "domain": domain,
        "attributes": markdown_list(p.attributes_for_type(domain)),
        "dta_in": markdown_list(
            [x.source for x in p.terules_query_raw(target=domain, tclass=["process"], perms=["transition"])]),
        "dta_out": markdown_list(
            [x.target for x in p.terules_query_raw(source=domain, tclass=["process"], perms=["transition"])]),
        "entrypoints": markdown_list(
            [x.target for x in p.terules_query_raw(source=domain, tclass=["file"], perms=["entrypoint"])]),
        "other_trans": markdown_code_from_results(
            p.transrules_query(source=domain, source_indirect=False, tclass=obj_classes_except_process)),
        "roles": markdown_list(p.roles_for_type(domain)),
        "capabilities": markdown_code_from_results(
            p.terules_query_raw(source=domain, tclass=["capability"], source_indirect=False)),
        "fread": markdown_code_from_results(
            p.terules_query_raw(source=domain, tclass=file_dir_classes, perms=["read"], source_indirect=False)),
        "fwrite": markdown_code_from_results(
            p.terules_query_raw(source=domain, tclass=file_dir_classes, perms=["write", "append"],
                                source_indirect=False)),
        "packet": markdown_code_from_results(
            p.terules_query_raw(source=domain, tclass=["packet"], source_indirect=False)),
        "process": markdown_code_from_results(
            p.terules_query_raw(source=domain, tclass=["process"], source_indirect=False)),
        "socket": markdown_code_from_results(
            p.terules_query_raw(source=domain, tclass="socket", tclass_regex=True, source_indirect=False))
    }

    return domain_summary_template.format(**data)


domain_attribute_summary_template = """
### Domain Attribute Summary: {attribute}

####  Types in Attribute

{types}

#### Capability Permissions

{capabilities}

#### File Read Permissions

{fread}

#### File Write Permissions

{fwrite}


#### Packet Permissions

{packet}

#### Process Permissions

{process}

#### Socket Permissions

{socket}

"""

file_attribute_summary_template = """
### File Attribute Summary: {file_type}

####  Types in Attribute

{types}

#### Transitions

{other_trans}

#### File Read Permissions

{fread}

#### File Write Permissions

{fwrite}

"""



file_summary_template = """
### File Type Summary: {file_type}

####  Type Attributes

{attributes}

#### Transitions

{other_trans}

#### File Read Permissions

{fread}

#### File Write Permissions

{fwrite}

"""





packet_summary_template = """
### Packet Type Summary: {packet_type}

####  Type Attributes

{attributes}

#### Packet Permissions

{packet}

"""


# Monkey patch to get some better __repr__ - these should be expanded over time
# to cover more types.
#
# With this you don't have to print the last statement - e.g.,
#
#     p.terules_query(source="smbd_t")
#
# You can also just use the built-in pretty printer (aliased a pp)
#
#    pp(p.terules_query(source="smbd_t"))

def str_repr(self):
    return str(self)


se.policyrep.typeattr.BaseType.__repr__ = str_repr
se.policyrep.terule.BaseTERule.__repr__ = str_repr
se.policyrep.role.BaseRole.__repr__ = str_repr

import subprocess
from pygments import highlight
from pygments.lexers import DiffLexer
from pygments.formatters import HtmlFormatter


def diff_to_html(diff_text):
    html = HtmlFormatter()
    return highlight(diff_text, DiffLexer(), html) + "<style>%s</style" % html.get_style_defs()


# PolicySource makes it easier to grep through the sources inside the notebook to
# find the policy statements granting the access we care about.
class RefPolicySource(object):
    def __init__(self, path):
        self.path = path
        self.abspath = os.path.abspath(self.path)
        self.modules_path = self.path + "/policy/modules"

    def grep(self, search_str, file_type, path=None, extended=False):
        if path is None:
            path = self.path
        return subprocess.run(["grep", "-r", "-n" ] + [ "--extended-regexp" ] * extended +
                              [ "--include", file_type, search_str, "."], cwd=path, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT).stdout.decode('utf-8')

    def diff(self, patha, pathb):
        return subprocess.run(["diff", "-u", pathb, patha], cwd=self.path,
                              stdout=subprocess.PIPE).stdout.decode('utf-8')

    def diff_relative(self, fname, other_source):
        return diff_to_html(self.diff(self.abspath + fname, other_source.abspath + fname))

    def find_def(self, name):
        return self.grep(name, "*.te", self.modules_path)

    def type_def(self, name):
        return self.find_def("type " + name)

    def attr_def(self, name):
        return self.find_def("attribute " + name)

    def file_contexts(self, type_name, extended=False):
        return self.grep(type_name, "*.fc", self.modules_path, extended)

    def genfscon(self, fs_type):
        return self.find_def("genfscon " + fs_type)

    def rules_search(self, search_str):
        return self.grep(search_str, "*", self.modules_path)

    def get_module(self, file_name):
        fd = open(self.modules_path + "/" + file_name)
        return fd.read()

    def diff_mls_constraints(self, other_source):
        return self.diff_relative("/policy/mls", other_source)

    def diff_mcs_constraints(self, other_source):
        return self.diff_relative("/policy/mcs", other_source)

    def diff_constraints(self, other_source):
        return self.diff_relative("/policy/constraints", other_source)


def load_refpolicy_source(path):
    return RefPolicySource(path)


if __name__ == '__main__':
    p = load_policy("policy.30")
    p.build_index_if_needed()

    # t = timeit.timeit(lambda: p.terules_query(source="smb", source_regex=True, source_indirect=True), number=4)
    # print(t)
    # t = timeit.timeit(lambda: p.terules_query_orig(source="smb", source_regex=True, source_indirect=True), number=4)
    # print(t)

    # print(domain_info_flow(p, "passwd_t", tclass=["file"]))

    p.domain_types()
    print(p.types_summary())
