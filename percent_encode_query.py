#!/usr/bin/env python
#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import logging
import optparse
import sys
from urllib import parse

logger = logging.getLogger(__name__)


def build_cli_parser() -> optparse.OptionParser:
    """
    Generate OptionParser to handle command line switches

    :return: optparse.OptionParser
    """
    usage = "usage: %prog [options]"
    desc = "Encode, using percent encoding, a Carbon Black query"

    cmd_parser = optparse.OptionParser(usage=usage, description=desc)

    cmd_parser.add_option("-q", "--query", action="store", type="string", dest="query",
                          help="Query to encode")
    cmd_parser.add_option("-n", "--no-prepend", action="store_false", default=True, dest="prepend",
                          help=('Do NOT prepend "q=" and "cb.urlver=1" when not found '
                                'in the query specified with "--query"'))
    return cmd_parser


def is_query_complete(query: str) -> bool:
    """
    Returns indication as to if query includes a q=, cb.q=, or cb.fq

    :param query: the query string to be checked
    :return: True if this looks like a CBR query
    """
    # check for raw query captured from the browser
    if query.startswith("cb.urlver="):
        return True

    # check for simpler versions
    if query.startswith("q=") or query.startswith("cb.q=") or query.startswith("cb.fq="):
        return True
    return False


if __name__ == "__main__":
    parser = build_cli_parser()
    options, args = parser.parse_args(sys.argv)

    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')

    if not options.query:
        logger.error("-> Must specify a query to encode; use the -q switch or --help for usage")
        sys.exit(0)

    logger.info(f"Converting `{options.query}`...")

    # unless overridden by operator, prepend a cb.urlver=1&q= to the query if 
    # if does not already exist.  this makes it possible for customer to copy and
    # paste query from CB UI, pass through this script, and add to a feed
    #
    # see CBAPI-7
    #
    prepend = "cb.urlver=1&q=" if options.prepend and not is_query_complete(options.query) else ""
    print("-" * 80 + f"\n   {prepend}" + parse.quote_plus(options.query) + "\n" + "-" * 80)
