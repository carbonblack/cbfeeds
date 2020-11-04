#!/usr/bin/env python
#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, Set, Tuple

import cbfeeds

logger = logging.getLogger(__name__)


################################################################################
# Utility Functions
################################################################################

def build_cli_parser() -> argparse.ArgumentParser:
    """
    generate ArgumentParser to handle command line switches.
    """
    desc = "Validate a Carbon Black Response feed"

    cmd_parser = argparse.ArgumentParser(description=desc)

    cmd_parser.add_argument("-f", "--feed_filename",
                            help="Feed Filename(s) to validate",
                            type=str, required=True, action="append")

    cmd_parser.add_argument("-p", "--pedantic",
                            help="Validates that no non-standard JSON elements exist",
                            action="store_true", default=False)

    cmd_parser.add_argument("-e", "--exclude",
                            help="Filename of 'exclude' list - newline delimited indicators to consider invalid",
                            default=None)

    cmd_parser.add_argument("-i", "--include",
                            help="Filename of 'include' list - newline delimited indicators to consider valid",
                            default=None)

    return cmd_parser


def validate_file(filename: str) -> str:
    """
    Validate that the file exists and is readable.

    :param filename: The name of the file to read
    :return: file contents
    """
    if filename.strip() == "" or not os.path.exists(filename):
        raise cbfeeds.CbException(f"No such feed file: `{filename}`")

    try:
        with open(filename, 'r') as fp:
            return fp.read()
    except Exception as err:
        raise cbfeeds.CbException(f"Unable to read feed file: `{filename}`: {err}")


def validate_json(contents: str) -> Dict[str, Any]:
    """
    Validate that the file is well-formed JSON.

    :param contents: file contents in supposed JSON format
    :return: json object
    """
    try:
        return json.loads(contents)
    except Exception as err:
        raise cbfeeds.CbException(f"Unable to process feed JSON: {err}")


def validate_feed(feed: Dict[str, Any], pedantic: bool = False) -> cbfeeds.CbFeed:
    """
    Validate that the file is valid as compared to the CB feeds schema.

    :param feed: the digested feed
    :param pedantic: If True, perform pedantic validation
    :return: CbFeed object
    """
    # verify that we have both of the required feedinfo and reports elements
    if "feedinfo" not in feed:
        raise cbfeeds.CbException("No 'feedinfo' element found!")
    if "reports" not in feed:
        raise cbfeeds.CbException("No 'reports' element found!")

    # Create the cbfeed object
    feed = cbfeeds.CbFeed(feed["feedinfo"], feed["reports"], strict=pedantic)

    # Validate the feed -- this validates that all required fields are present, and that
    #    all required values are within valid ranges
    feed.validate()

    return feed


def validate_against_include_exclude(feed: cbfeeds.CbFeed, include: Set, exclude: Set) -> None:
    """
    Ensure that no feed indicators are 'excluded' or blacklisted.

    :param feed: feed to be validated
    :param include: set of included IOCs
    :param exclude: set of excluded IOCs
    """
    for ioc in feed.iter_iocs():
        if ioc["ioc"] in exclude and not ioc["ioc"] in include:
            raise Exception(ioc)


def gen_include_exclude_sets(include_filename: str = None, exclude_filename: str = None) -> Tuple[Set, Set]:
    """
    Generate an include and an exclude set of indicators by reading indicators from flat, newline-delimited files.

    :param include_filename: path to file containing include entries
    :param exclude_filename: path to file containing exclude entries
    """
    include = set()
    exclude = set()

    if include_filename:
        if not os.path.exists(include_filename):
            raise cbfeeds.CbException(f"No such include file: {include_filename}")
        for indicator in open(include_filename).readlines():
            include.add(indicator.strip())

    if exclude_filename:
        if not os.path.exists(exclude_filename):
            raise cbfeeds.CbException(f"No such include file: {exclude_filename}")
        for indicator in open(exclude_filename).readlines():
            exclude.add(indicator.strip())

    return include, exclude


def validation_cycle(filename: str) -> bool:
    """
    Generate include and exclude (whitelist and blacklist) sets of indicators. Feed validation will fail if a feed
    ioc is blacklisted unless it is also whitelisted.

    :param filename: filename contaning feed information
    :return: False if there were problems, True if ok
    """
    include, exclude = gen_include_exclude_sets(options.include, options.exclude)

    try:
        contents = validate_file(filename)
    except Exception as err:
        logger.error(f"Feed file invalid: {err}")
        return False

    try:
        jsondict = validate_json(contents)
    except Exception as err:
        logger.error(f"Feed json for `{filename}` is invalid: {err}")
        return False

    try:
        feed = validate_feed(jsondict)
    except Exception as err:
        logger.error(f"Feed `{filename}` is invalid: {err}")
        return False

    if len(exclude) > 0 or len(include) > 0:
        try:
            validate_against_include_exclude(feed, include, exclude)
            logger.info(" ... validated against include and exclude lists")
        except Exception as err:
            logger.error(f" ... unnable to validate against the include and exclude lists:\n{err}")
            return False

    extra = "" if not options.pedantic else " and contains no non-CB elements"
    logger.info(f"Feed `{filename}` is good{extra}!")
    return True


################################################################################
# Main
################################################################################

if __name__ == "__main__":
    parser = build_cli_parser()
    options = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')

    feed_filenames = options.feed_filename
    if not feed_filenames:
        logger.error("-> Must specify one or more feed filenames to validate; use the -f switch or --help for usage")
        sys.exit(0)

    sep = False
    for feed_filename in feed_filenames:
        if sep:
            logger.info('\n ----- \n')
        validation_cycle(feed_filename)
        sep = True
