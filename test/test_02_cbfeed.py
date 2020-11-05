#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import json

import cbfeeds
from common import TestCommon


class TestCbFeedMethods(TestCommon):
    """
    Validate the core methods of the CBFeed class.
    """

    # ----- Basic Validation  ----------------------------------------- #

    def test_01_validate_feed(self):
        """
        Verify that overall feed validation works.
        """
        _, feed = self._load_feed_file()
        feed.validate()

    def test_02_validate_feed_serialized(self):
        """
        Verify that overall feed validation works with serialized data.
        """
        _, feed = self._load_feed_file()
        feed.validate(serialized_data=feed.dump())

    # ----- Method validation  ----------------------------------------- #

    def test_03a_neg_validate_feedinfo_missing(self):
        """
        Verify that CBFeed.validate detects missing feedinfo.
        """
        _, feed = self._load_feed_file()
        del feed.data['feedinfo']
        try:
            feed.validate()
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feed missing 'feedinfo' data" in err.args[0]

    def test_03b_neg_validate_feedinfo_missing_serialized(self):
        """
        Verify that CBFeed.validate detects missing feedinfo in serialized mode.
        """
        info, feed = self._load_feed_file()
        del info['feedinfo']
        try:
            feed.validate(serialized_data=json.dumps(info))
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feed missing 'feedinfo' data" in err.args[0]

    def test_04a_neg_validate_reports_missing(self):
        """
        Verify that CBFeed.validate detects missing reports.
        """
        _, feed = self._load_feed_file()
        del feed.data['reports']
        try:
            feed.validate()
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feed missing 'reports' structure" in err.args[0]

    def test_04b_neg_validate_reports_missing_serialized(self):
        """
        Verify that CBFeed.validate detects missing reports in serialized mode.
        """
        info, feed = self._load_feed_file()
        del info['reports']
        try:
            feed.validate(serialized_data=json.dumps(info))
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feed missing 'reports' structure" in err.args[0]

    def test_05a_neg_validate_feed_strict_bad_feedinfo(self):
        """
        Verify that CBFeed.validate detects non-CB feedinfo fields if strict.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['booga'] = "foobar"
        try:
            feed = cbfeeds.CbFeed(info['feedinfo'], info['reports'])
            feed.validate(strict=True)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Problem with feed `QA Feed BWF912316192`: Feedinfo includes unknown field: booga" in err.args[0]

    def test_05b_neg_validate_feed_strict_bad_report(self):
        """
        Verify that CBFeed.validate detects non-CB feedinfo fields if strict.
        """
        info, _ = self._load_feed_file()
        info['reports'][1]['booga'] = "foobar"
        try:
            feed = cbfeeds.CbFeed(info['feedinfo'], info['reports'])
            feed.validate(strict=True)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Problem with feed `QA Feed BWF912316192`, report `WithSha256`: Report includes "
                    f"unknown field: booga") in err.args[0]

    def test_06_neg_validate_reports_list_dup_id(self):
        """
        Verify that validate_report_list detects duplicate ids.
        """
        info, feed = self._load_feed_file()
        reports = info['reports']
        reports[0]['id'] = reports[1]['id']

        try:
            feed.validate_report_list(reports)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Duplicate report id 'WithSha256" in err.args[0]

    def test_07_validate_iter_iocs(self):
        """
        Verify that iter_iocs returns all iocs properly.
        """
        _, feed = self._load_feed_file()

        checkoff = {'md5|dbb379c9337cc31b24743e7cf81ee8bd': True,
                    'sha256|94dcf0531121e13a73114e8806f096d31e21dab4a8b1bfef95b5e0171a9a0556': True,
                    'ipv4|158.106.122.248': True,
                    'ipv6|7F1F:67E6:4BA0:5935:453A:A3AA:D69C:6146': True,
                    'dns|spend.policy.issue.net': True,
                    'ja3|07f362079e7f3d5a8855549fcc9a441e': True,
                    'ja3s|0fa6b3b35df905b209742cf80c06f7da': True,
                    'query|process_name:foobar.exe': True,
                    }
        extras = []
        for item in feed.iter_iocs():
            key = f"{item['type']}|{item['ioc']}"
            if key in checkoff:
                del checkoff[key]
            else:
                extras.append(key)

    def test_07_validate_dump(self):
        """
        Verify that dump() works as expected.
        """
        info, feed = self._load_feed_file()
        check = feed.dump()
        assert check == json.dumps(info, indent=2, sort_keys=True)
