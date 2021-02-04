#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import logging
import sys
import unittest


class TestCbFeedExamples(unittest.TestCase):
    # NOTE: zeus tracker returns: "# ZeuS Tracker has been discontinued on Jul 8th, 2019", so
    #       test_abusech has been removed.

    def test_mdl(self):
        import example.mdl as mdl
        mdl.generate_mdl_feed.DAYS_BACK = None  # get all data
        mdl.create()

    def test_tor(self):
        import example.tor as tor
        tor.create()


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='[%(filename)s:%(lineno)d] %(message)s')

    # run the unit tests
    #
    unittest.main()
