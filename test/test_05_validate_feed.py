#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import os

import cbfeeds
import validate_feed
from common import TestCommon


class TestValidateFeed(TestCommon):
    """
    Verify that the validate_feed utility methods work as expected.
    """

    def test_01a_neg_file_missing(self):
        """
        Verify that a non-existant file is trapped
        """
        try:
            validate_feed.validate_file("./nonesuch.json")
            self.fail("Did not get expected exception!")
        except cbfeeds.CbException:
            pass

    def test_01b_neg_file_unreadable(self):
        """
        Verify that a file that cannot be read is trapped.
        """
        info, feed = self._load_feed_file()
        os.chmod(self._test_feed, mode=0o000)

        try:
            validate_feed.validate_file(self._test_feed)
            self.fail("Did not get expected exception!")
        except cbfeeds.CbException:
            pass

    def test_02_neg_not_json(self):
        """
        Verify that non-json file contents are trapped
        """
        try:
            validate_feed.validate_json("This is not JSON!")
            self.fail("Did not get expected exception!")
        except cbfeeds.CbException:
            pass

    def test_03a_neg_missing_feedinfo(self):
        """
        Verify that feed information missing a feedinfo entry is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']
        try:
            validate_feed.validate_feed(info)
            self.fail("Did not get expected exception!")
        except cbfeeds.CbException as err:
            assert "No 'feedinfo' element found!" in f"{err}"

    def test_03b_neg_missing_reports(self):
        """
        Verify that feed information missing a reports entry is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports']
        try:
            validate_feed.validate_feed(info)
            self.fail("Did not get expected exception!")
        except cbfeeds.CbException as err:
            assert "No 'reports' element found!" in f"{err}"
