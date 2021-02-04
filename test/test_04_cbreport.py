#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import cbfeeds
from cbfeeds.feed import CbReport
from common import TestCommon


class TestCbReportMethods(TestCommon):
    """
    Validate the methods in the CbReport class.
    """

    def test_00a_init_unknown_key(self):
        """
        Verify that an initialized feedinfo object only retains known keys.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['foobar'] = "should vanish"
        cr = CbReport(**info['reports'][0])
        assert "foobar" not in cr.data

    def test_00b_neg_init_unknown_key_strict(self):
        """
        Verify that an initialized feedinfo object only retains known keys.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['foobar'] = "should vanish"
        try:
            CbReport(strict=True, **info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report includes unknown field: foobar" in err.args[0]

    def test_00c_validate_unknown_key_unstrict(self):
        """
        Verify that validate with strict=False will turn off strictness in addition to validation.
        """
        info, _ = self._load_feed_file()
        cr = CbReport(strict=True, **info['reports'][0])
        cr._data['foobar'] = "should vanish"
        cr.validate(strict=False)
        assert "foobar" not in cr.data
        assert not cr.strict

    def test_00d_neg_validate_unknown_key_strict(self):
        """
        Verify that an initialized feedinfo object only retains known keys.
        """
        info, _ = self._load_feed_file()
        cr = CbReport(**info['reports'][0])
        cr._data['foobar'] = "should vanish"
        try:
            cr.validate(strict=True)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report includes unknown field: foobar" in err.args[0]
            assert cr.strict

    def test_01a_update_unknown_key(self):
        """
        Verify that updated feedinfo data only retains known keys.
        """
        info, _ = self._load_feed_file()
        cfi = CbReport(**info['reports'][0])
        info['reports'][0]['foobar'] = "should vanish"
        cfi.data = info['reports'][0]
        assert "foobar" not in cfi.data

    def test_01b_neg_update_unknown_key_strict(self):
        """
        Verify that updated feedinfo data only retains known keys.
        """
        info, _ = self._load_feed_file()
        cfi = CbReport(strict=True, **info['reports'][0])
        info['reports'][0]['foobar'] = "should vanish"
        try:
            cfi.data = info['reports'][0]
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report includes unknown field: foobar" in err.args[0]

    # ----- Tests exclusive to the __init__() method ------------------------------

    def test_02_init_no_timestamp(self):
        """
        Verify that on init a tampstamp is created, if not provided.
        """
        info, _ = self._load_feed_file()
        if 'timestamp' in info['reports'][0]:
            del info['reports'][0]['timestamp']

        rp = CbReport(validate=False, **info['reports'][0])
        assert rp.data['timestamp'] is not None

    # ----- validate() method testing --------------------------------------------------

    def test_03a_neg_validate_id_missing(self):
        """
        Verify that missing "id" is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['id']

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report missing required field(s): id" in err.args[0]

    def test_03b_neg_validate_iocs_missing(self):
        """
        Verify that missing "iocs" is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['iocs']

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report missing required field(s): iocs" in err.args[0]

    def test_03c_neg_validate_link_missing(self):
        """
        Verify that missing "link" is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['link']

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report missing required field(s): link" in err.args[0]

    def test_03d_neg_validate_score_missing(self):
        """
        Verify that missing "score" is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['score']

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report missing required field(s): score" in err.args[0]

    def test_03e_neg_validate_timestamp_missing(self):
        """
        Verify that missing "timestamp" is detected.

        NOTE: timestamp always filled in on init, so it generally cannot go missing unless mangled.
        """
        info, _ = self._load_feed_file()

        try:
            cr = CbReport(**info['reports'][0], validate=False)
            del cr.data['timestamp']
            cr.validate()
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report missing required field(s): timestamp" in err.args[0]

    def test_03f_neg_validate_title_missing(self):
        """
        Verify that missing "title" is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['title']

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report missing required field(s): title" in err.args[0]

    def test_04a_validate_optional_description_missing(self):
        """
        Verify that description is optional and not required.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['description']
        cr = CbReport(**info['reports'][0])
        assert 'description' not in cr.data

    def test_04b_validate_optional_tags_missing(self):
        """
        Verify that tags is optional list is detected.
        """
        info, _ = self._load_feed_file()
        del info['reports'][0]['tags']
        cr = CbReport(**info['reports'][0])
        assert 'tags' not in cr.data

    def test_05a_neg_validate_description_not_str(self):
        """
        Verify that "description" not a string is detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['description'] = 42

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'description', must be of type str or bytes" in err.args[0]

    def test_05b_neg_validate_id_not_str(self):
        """
        Verify that "id" not a string is detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['id'] = 42

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report '42', field 'id', must be of type str or bytes" in err.args[0]

    def test_05c_neg_validate_link_not_str(self):
        """
        Verify that "link" not a string is detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['link'] = 42

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'link', must be of type str or bytes" in err.args[0]

    def test_05d_neg_validate_title_not_str(self):
        """
        Verify that "title" not a string is detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['title'] = 42

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'title', must be of type str or bytes" in err.args[0]

    def test_06a_neg_validate_score_not_int(self):
        """
        Verify that "score" not a int is detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = "bogus"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'score', must be an int" in err.args[0]

    def test_06b_validate_score_is_float(self):
        """
        Verify that "score" as a float is converted to int.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = 15.67
        cr = CbReport(**info['reports'][0])
        assert cr.data['score'] == 15

    def test_06c_neg_validate_timestamp_not_int(self):
        """
        Verify that "timestamp" not a int is detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['timestamp'] = "bogus"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'timestamp', must be an int" in err.args[0]

    def test_07a_neg_validate_tags_not_list(self):
        """
        Verify that if "tags" is not a list we detect this.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['tags'] = "md5"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'tags', must be a list of str" in err.args[0]

    def test_07b_neg_validate_tags_not_str_entry(self):
        """
        Verify that non-string entries in "tags" are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['tags'] = ["md5", 42]

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'tag', has entry not a string" in err.args[0]

    def test_07c_neg_validate_tags_not_alphanumeric_entry(self):
        """
        Verify that non-alphanumeric string entries in "tags" are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['tags'] = ["md5", "sha-256"]

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'tag', has an entry that is not alphanumeric" in err.args[0]

    def test_07d_neg_validate_tags_empty_string_entry(self):
        """
        Verify that string entries that are empty string are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['tags'] = ["md5", ""]

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'tag', has an entry that is not 1-32 characters in length" in err.args[0]

    def test_07e_neg_validate_tags_long_string_entry(self):
        """
        Verify that string entries that are over 32 characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['tags'] = ["md5", "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"]

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'tag', has an entry that is not 1-32 characters in length" in err.args[0]

    def test_08a_neg_validate_score_negative_when_disallowed(self):
        """
        Verify that when allow_negative_scores is False we detect negative scores.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = -10

        try:
            CbReport(**info['reports'][0], allow_negative_scores=False)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'score' (-10), out of range 0 to 100" in err.args[0]

    def test_08b_validate_score_negative_when_allowed(self):
        """
        Verify that when allow_negative_scores is True we allow negative scores.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = -10
        CbReport(**info['reports'][0], allow_negative_scores=True)

    def test_08c_neg_validate_score_too_low(self):
        """
        Verify that we detect scores too low.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = -101

        try:
            CbReport(**info['reports'][0], allow_negative_scores=True)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'score' (-101), out of range -100 to 100" in err.args[0]

    def test_08d_neg_validate_score_too_high(self):
        """
        Verify that we detect scores too high.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = 101

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'score' (101), out of range 0 to 100" in err.args[0]

    def test_08d_neg_validate_score_too_high_neg_allowed(self):
        """
        Verify that we detect scores too high.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['score'] = 101

        try:
            CbReport(**info['reports'][0], allow_negative_scores=True)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'score' (101), out of range -100 to 100" in err.args[0]

    def test_09a_validate_id_all_allowed_chars(self):
        """
        Validate all allowed characters for id..
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['id'] = "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ-01234.56789"
        CbReport(**info['reports'][0])

    def test_09b_neg_validate_id_disallowed_spaces(self):
        """
        Verify that we detect scores too high.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['id'] = "cant have spaces"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'cant have spaces' (the id) is invalid and may only contain" in err.args[0]

    def test_09c_neg_validate_id_disallowed_special(self):
        """
        Verify that we detect scores too high.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['id'] = "no$special"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'no$special' (the id) is invalid and may only contain" in err.args[0]

    def test_10a_neg_validate_iocs_bad_format(self):
        """
        Verify that we detect an iocs section with an incorrect format (attempted list of dict).
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs'] = [{"ipv4": ["158.106.122.248"]}]

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', has bad format (must be dict)" in err.args[0]

    def test_10b_neg_validate_iocs_empty(self):
        """
        Verify that we detect an iocs section with no entries.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs'] = {}

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', has no entries" in err.args[0]

    def test_10c_neg_validate_iocs_entry_not_list(self):
        """
        Verify that we detect an iocs entry that is not a list of string (supposed bad formatting).
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['md5'] = "0fa6b3b35df905b209742cf80c06f7da"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', ioc 'md5', is not a list of str" in err.args[0]

    def test_10d_neg_validate_iocs_entry_empty_list(self):
        """
        Verify that we detect an iocs entry that is empty.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['md5'] = []

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', ioc 'md5', must have at least 1 entry" in err.args[0]

    def test_10e_neg_validate_iocs_entry_contains_non_str(self):
        """
        Verify that we detect an iocs entry that has a non-string entry.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['md5'] = [43]

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', ioc 'md5', has non-str entry" in err.args[0]

    def test_10f_neg_validate_iocs_entry_unknown_type(self):
        """
        Verify that if not pedantic, unknown types are left alone.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['foobar'] = ["43.5.66.90"]
        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', unknown ioc 'foobar'" in err.args[0]

    def test_10g_validate_query_ioc_extra_keys(self):
        """
        Verify that query iocs don't have extra keys.
        """
        info, _ = self._load_feed_file()
        info['reports'][2]['iocs']['query']['foobar'] = ["process_name:foobar.exe"]
        cr = CbReport(**info['reports'][2])
        assert 'foobar' not in cr.data['iocs']['query']

    def test_10h_neg_validate_query_ioc_extra_keys_strict(self):
        """
        Verify that query iocs don't have extra keys.
        """
        info, _ = self._load_feed_file()
        info['reports'][2]['iocs']['query']['foobar'] = ["process_name:foobar.exe"]
        try:
            CbReport(strict=True, **info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithQueryEvent', field 'ioc' query includes unknown field: foobar" in err.args[0]

    def test_11a_neg_validate_query_ioc_missing_index_type(self):
        """
        Verify that query iocs have the index_type section.
        """
        info, _ = self._load_feed_file()
        del info['reports'][2]['iocs']['query']['index_type']

        try:
            CbReport(**info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithQueryEvent', field 'iocs', 'query' section missing 'index_type'" in err.args[0]

    def test_11b_neg_validate_query_ioc_not_dict(self):
        """
        Verify that query iocs have the proper format.
        """
        info, _ = self._load_feed_file()
        info['reports'][2]['iocs']['query'] = ["process_name:foobar.exe"]

        try:
            CbReport(**info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithQueryEvent', field 'iocs', ioc 'query', is not a dictionary" in err.args[0]

    def test_11c_neg_validate_query_ioc_index_type_empty(self):
        """
        Verify that query iocs have the index_type section, and that empty values are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][2]['iocs']['query']['index_type'] = ""

        try:
            CbReport(**info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithQueryEvent', field 'iocs', 'index_type' is not a known type ()" in err.args[0]

    def test_11d_neg_validate_query_ioc_index_type_invalid(self):
        """
        Verify that query iocs have the index_type section, and that empty values are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][2]['iocs']['query']['index_type'] = "foobar"

        try:
            CbReport(**info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithQueryEvent', field 'iocs', 'index_type' is not a known type (foobar)" in err.args[0]

    def test_11e_neg_validate_query_ioc_missing_search_query(self):
        """
        Verify that query iocs have the search_query section.
        """
        info, _ = self._load_feed_file()
        del info['reports'][2]['iocs']['query']['search_query']

        try:
            CbReport(**info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithQueryEvent', field 'iocs', 'query' section missing 'search_query'" in err.args[0]

    def test_12a_validate_query_ioc_good_query(self):
        """
        Verify that query iocs have the search_query section.
        """
        info, _ = self._load_feed_file()
        CbReport(**info['reports'][2])

    def test_12b_validate_query_ioc_good_module_query(self):
        """
        Verify that query iocs have the search_query section.
        """
        info, _ = self._load_feed_file()
        CbReport(**info['reports'][3])

    def test_13a_neg_validate_query_ioc_search_query_invald_chars(self):
        """
        Verify that query iocs have valid characters in the query.
        """
        info, _ = self._load_feed_file()
        info['reports'][2]['iocs']['query']['search_query'][0] = 'cb.urlver=1&q=process_name:notepad.exe'

        try:
            CbReport(**info['reports'][2])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithQueryEvent', field 'iocs', 'query' has unescaped non-reserved character ':' "
                    "found in query; use percent-encoding") in err.args[0]

    def test_14a_neg_validate_md5_ioc_too_short(self):
        """
        Verify that md5 iocs that are truncated are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['md5'][0] = "abcdef"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', 'mp5' has invalid hash" in err.args[0]

    def test_14b_neg_validate_md5_ioc_too_long(self):
        """
        Verify that md5 iocs that are extended are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['md5'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', 'mp5' has invalid hash" in err.args[0]

    def test_14c_neg_validate_md5_ioc_invalid_chars(self):
        """
        Verify that md5 iocs that have invalid characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][0]['iocs']['md5'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccXX"

        try:
            CbReport(**info['reports'][0])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithMd5', field 'iocs', 'mp5' has invalid hash" in err.args[0]

    def test_15a_neg_validate_ja3_ioc_too_short(self):
        """
        Verify that ja3 iocs that are truncated are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][7]['iocs']['ja3'][0] = "abcdef"

        try:
            CbReport(**info['reports'][7])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithJa3', field 'iocs', 'ja3' has invalid hash" in err.args[0]

    def test_15b_neg_validate_ja3_ioc_too_long(self):
        """
        Verify that ja3 iocs that are extended are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][7]['iocs']['ja3'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"

        try:
            CbReport(**info['reports'][7])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithJa3', field 'iocs', 'ja3' has invalid hash" in err.args[0]

    def test_15c_neg_validate_ja3_ioc_invalid_chars(self):
        """
        Verify that ja3 iocs that have invalid characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][7]['iocs']['ja3'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccXX"

        try:
            CbReport(**info['reports'][7])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithJa3', field 'iocs', 'ja3' has invalid hash" in err.args[0]

    def test_16a_neg_validate_ja3s_ioc_too_short(self):
        """
        Verify that ja3s iocs that are truncated are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][8]['iocs']['ja3s'][0] = "abcdef"

        try:
            CbReport(**info['reports'][8])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithJa3s', field 'iocs', 'ja3s' has invalid hash" in err.args[0]

    def test_16b_neg_validate_ja3s_ioc_too_long(self):
        """
        Verify that ja3s iocs that are extended are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][8]['iocs']['ja3s'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"

        try:
            CbReport(**info['reports'][8])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithJa3s', field 'iocs', 'ja3s' has invalid hash" in err.args[0]

    def test_16c_neg_validate_ja3s_ioc_invalid_chars(self):
        """
        Verify that ja3s iocs that have invalid characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][8]['iocs']['ja3s'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccXX"

        try:
            CbReport(**info['reports'][8])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithJa3s', field 'iocs', 'ja3s' has invalid hash" in err.args[0]

    def test_17a_neg_validate_sha256_ioc_too_short(self):
        """
        Verify that sha256 iocs that are truncated are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][1]['iocs']['sha256'][0] = "aaaaaaaaaabbbbbbbbbbcccccccccc22"

        try:
            CbReport(**info['reports'][1])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithSha256', field 'iocs', 'sha256' has invalid hash" in err.args[0]

    def test_17b_neg_validate_sha256_ioc_too_long(self):
        """
        Verify that sha256 iocs that are extended are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][1]['iocs']['sha256'][
            0] = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff0000000000"

        try:
            CbReport(**info['reports'][1])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithSha256', field 'iocs', 'sha256' has invalid hash" in err.args[0]

    def test_17c_neg_validate_sha256_ioc_invalid_chars(self):
        """
        Verify that sha256 iocs that have invalid characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][1]['iocs']['sha256'][0] = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffXXXX"

        try:
            CbReport(**info['reports'][1])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithSha256', field 'iocs', 'sha256' has invalid hash" in err.args[0]

    def test_18a_neg_validate_ipv4_ioc_too_short(self):
        """
        Verify that ipv4 iocs that are truncated are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][4]['iocs']['ipv4'][0] = "11.22.33"

        try:
            CbReport(**info['reports'][4])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv4', field 'iocs', 'ipv4' value of '11.22.33' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_18b_neg_validate_ipv4_ioc_too_long(self):
        """
        Verify that ipv4 iocs that are padded are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][4]['iocs']['ipv4'][0] = "11.22.33.44.55"

        try:
            CbReport(**info['reports'][4])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv4', field 'iocs', 'ipv4' value of '11.22.33.44.55' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_18c_neg_validate_ipv4_ioc_missing_part(self):
        """
        Verify that ipv4 iocs that are missing parts are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][4]['iocs']['ipv4'][0] = "11.22..44"

        try:
            CbReport(**info['reports'][4])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv4', field 'iocs', 'ipv4' value of '11.22..44' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_18d_neg_validate_ipv4_ioc_bogus(self):
        """
        Verify that ipv4 iocs that are bogus are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][4]['iocs']['ipv4'][0] = "foo.bar.com"

        try:
            CbReport(**info['reports'][4])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv4', field 'iocs', 'ipv4' value of 'foo.bar.com' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_19a_neg_validate_ipv6_ioc_too_short(self):
        """
        Verify that ipv6 iocs that are truncated are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][5]['iocs']['ipv6'][0] = "0000:1111:2222:3333"

        try:
            CbReport(**info['reports'][5])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv6', field 'iocs', 'ipv6' value of '0000:1111:2222:3333' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_19b_neg_validate_ipv6_ioc_too_long(self):
        """
        Verify that ipv6 iocs that are extended are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][5]['iocs']['ipv6'][0] = "0000:1111:2222:3333:4444:5555:6666:7777:8888:9999"

        try:
            CbReport(**info['reports'][5])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv6', field 'iocs', 'ipv6' value of "
                    "'0000:1111:2222:3333:4444:5555:6666:7777:8888:9999' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_19c_neg_validate_ipv6_ioc_invalid_chars(self):
        """
        Verify that ipv6 iocs that have invalid characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][5]['iocs']['ipv6'][0] = "0000:1111:2222:oooo:4444:5555:6666:7777"  # o, not 0

        try:
            CbReport(**info['reports'][5])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithIpv6', field 'iocs', 'ipv6' value of "
                    "'0000:1111:2222:oooo:4444:5555:6666:7777' does not appear"
                    " to be an IPv4 or IPv6 address") in err.args[0]

    def test_19d_validate_ipv6_ioc_compressed(self):
        """
        Verify that ipv6 iocs that used compressed format are accepted.
        """
        info, _ = self._load_feed_file()
        info['reports'][5]['iocs']['ipv6'][0] = "1:22:333:4444::6666:7777"  # same as 0001:0022:0333:4444:0000:6666:7777
        CbReport(**info['reports'][5])

    def test_20a_validate_dns_ioc(self):
        """
        Verify that basic dns strings are allowed.
        """
        info, _ = self._load_feed_file()
        CbReport(**info['reports'][6])

    def test_20b_neg_validate_dns_ioc_empty(self):
        """
        Verify that dns entries that are empty string are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][0] = ""

        try:
            CbReport(**info['reports'][6])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithDns', field 'iocs', 'dns' is empty" in err.args[0]

    def test_20c_neg_validate_dns_ioc_over_253_char(self):
        """
        Verify that dns entries that are exceed the spec limit of 253 characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][0] = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".com"

        try:
            CbReport(**info['reports'][6])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithDns', field 'iocs', 'dns' exceeds maximum size of 253 characters" in err.args[0]

    def test_20c_neg_validate_dns_ioc_too_few_octets(self):
        """
        Verify that dns entries with only 1 octet are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][0] = "foobar"

        try:
            CbReport(**info['reports'][6])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithDns', field 'iocs', 'dns' value has too few octets (foobar)" in err.args[0]

    # NOTE: Spec limits dns to 127 octets, but you will hit total length limits before you hit this

    def test_20d_neg_validate_dns_ioc_empty_octet(self):
        """
        Verify that dns entries with empty octets are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][0] = "foobar..com"

        try:
            CbReport(**info['reports'][6])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithDns', field 'iocs', 'dns' is invalid : foobar..com" in err.args[0]

    def test_20e_neg_validate_dns_ioc_octet_over_63_char(self):
        """
        Verify that dns entries with octets over 63 characters are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][
            0] = "foobar.aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffgggggggggg.com"

        try:
            CbReport(**info['reports'][6])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert ("Report 'WithDns', field 'iocs', 'dns' is invalid : foobar.aaaaaaaaaabbbbbbbbbbcccccccccc"
                    "ddddddddddeeeeeeeeeeffffffffffgggggggggg.com") in err.args[0]

    def test_20e_validate_dns_ioc_octet_starts_with_number(self):
        """
        Verify that dns entries with octets starting with a number are allowed (not fully to spec, but seems to
        be seen in external source data)
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][0] = "foobar.4chan.com"
        CbReport(**info['reports'][6])

    def test_20f_neg_validate_dns_ioc_octet_starts_with_hyphen(self):
        """
        Verify that dns entries with octets starting with a number are detected.
        """
        info, _ = self._load_feed_file()
        info['reports'][6]['iocs']['dns'][0] = "foobar.-chan.com"

        try:
            CbReport(**info['reports'][6])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidReport as err:
            assert "Report 'WithDns', field 'iocs', 'dns' is invalid : foobar.-chan.com" in err.args[0]
