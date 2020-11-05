#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import cbfeeds
from common import TestCommon


class TestCommonIntegrity(TestCommon):
    """
    Verify that the unit test common methods work as expected.
    """

    def test_01_neg_feedinfo_missing(self):
        """
        Verify that missing feed info is trapped.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']
        try:
            self._save_test_feed(info)
            self.fail("Did not get expected exception!")
        except KeyError:
            pass

    def test_02_neg_feedinfo_not_dict(self):
        """
        Verify that missing feed info is trapped.
        """
        info, _ = self._load_feed_file()
        info['feedinfo'] = "bogus"
        try:
            self._save_test_feed(info)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The supplied `feedinfo` parameter does not appear to be a valid dictionary" in err.args[0]

    def test_03_neg_feedinfo_empty_dict(self):
        """
        Verify that missing feed info is trapped.
        """
        info, _ = self._load_feed_file()
        info['feedinfo'] = {}
        try:
            feed = self._save_test_feed(info)
            feed.validate()
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo missing required field(s)" in err.args[0]

    def test_04_neg_reports_missing(self):
        """
        Verify that missing reports info is trapped.
        """
        info, _ = self._load_feed_file()
        del info['reports']
        try:
            self._save_test_feed(info)
            self.fail("Did not get expected exception!")
        except KeyError:
            pass

    def test_05_neg_reports_not_list(self):
        """
        Verify that invalid reports info (not list) is trapped.
        """
        info, _ = self._load_feed_file()
        info['reports'] = "bogus"
        try:
            self._save_test_feed(info)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The supplied `reports` parameter does not appear to be a valid list" in err.args[0]

    def test_06_neg_reports_not_list_of_dict(self):
        """
        Verify that invalid reports info (list item not dict) is trapped.
        """
        info, _ = self._load_feed_file()
        info['reports'] = ["bogus"]
        try:
            self._save_test_feed(info)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The `reports` parameter must be a list of dictionaries" in err.args[0]

    def test_10_cbfeed_using_cbfeedinfo_object(self):
        """
        Verify that a CbFeedInfo object can be used in creating a CbFeed object.
        """
        info, feed = self._load_feed_file()
        fi = cbfeeds.CbFeedInfo(**info['feedinfo'])
        cbf = cbfeeds.CbFeed(fi, info['reports'])
        assert cbf.dump() == feed.dump()

    def test_11_cbfeed_using_list_of_cbreport_objects(self):
        """
        Verify that a CbFeedInfo object can be used in creating a CbFeed object.
        """
        info, feed = self._load_feed_file()
        rp = [cbfeeds.CbReport(**rep) for rep in info['reports']]
        cbf = cbfeeds.CbFeed(info['feedinfo'], rp)
        assert cbf.dump() == feed.dump()

