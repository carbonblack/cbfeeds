#
# CARBON BLACK FEED GEN TESTS
# Copyright, Bit9, Inc 2014
#

import unittest
import sys
import os

class CbFeedTest(unittest.TestCase):
    def test_mdl(self):
        import example.mdl as mdl
        mdl.create()

    def test_tor(self):
        import example.tor as tor
        tor.create()

    def test_abusech(self):
        import example.abuse_ch as ach
        ach.create()

if __name__ == '__main__':
    # run the unit tests
    #
    unittest.main()
