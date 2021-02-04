#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import json
import os
import unittest
from typing import Any, Dict, Tuple

import cbfeeds

HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESOURCE_PATH_PREFIX = os.path.join(HOME, 'test', 'resources')


class TestCommon(unittest.TestCase):
    """
    Common class for all tests.
    """

    # standard test feed file
    _test_feed = "./testfeed.json"

    def tearDown(self):
        self._clear_test_feed()

    def _clear_test_feed(self) -> None:
        """
        Remove any local test feeds, if they exist.
        """
        if os.path.exists(self._test_feed):
            os.chmod(self._test_feed, mode=0o777)
            os.remove(self._test_feed)

    def _load_feed_file(self, source: str = None) -> Tuple[Dict[str, Any], cbfeeds.CbFeed]:
        """
        Copy template feed file into memory, mangle as needed, save locally for testing.

        :param source: Alternate template file to read
        :return: Tuple of json object (to optionally mangle) and feed object
        """
        use_source = "template.json" if source is None else source
        with open(os.path.join(RESOURCE_PATH_PREFIX, use_source), 'r') as fp:
            json_obj = json.load(fp)
        self._save_test_feed(json_obj)

        feed = cbfeeds.CbFeed(json_obj["feedinfo"], json_obj["reports"])
        return json_obj, feed

    def _save_test_feed(self, json_obj: Dict[str, Any]) -> cbfeeds.CbFeed:
        """
        Save json object (potentially mangled) to test feed file.

        :param json_obj: source json
        :return: potentially mangled feed object
        """
        with open(self._test_feed, 'w') as fp:
            json.dump(json_obj, fp, indent=4, sort_keys=True)
        feed = cbfeeds.CbFeed(json_obj["feedinfo"], json_obj["reports"])
        return feed
