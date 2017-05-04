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

from . import span
import sys
from sh import pandoc

def output_summary(p, fp, domain):
    fp.write(span.domain_summary_raw(p, domain))

def run(p, outfile_name, domains):
    outfile_md_name = outfile_name + ".md"

    md_fd = open(outfile_md_name, "w")
    for domain in domains:
        output_summary(p, md_fd, domain)

    md_fd.close()

    pandoc("-s", "-o", outfile_name, outfile_md_name)

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("domain_summary_to_word.py POLICY OUTFILE DOMAIN [DOMAIN_LIST]")
        sys.exit(1)

    policy_name = sys.argv[1]
    outfile_name = sys.argv[2]

    p = span.load_policy(policy_name)
    domains = [x.strip() for x in sys.argv[3:]]

    run(p, outfile_name, domains)


