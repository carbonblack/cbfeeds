#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import base64
import os

import cbfeeds
from cbfeeds.feed import CbFeedInfo
from common import TestCommon

RESOURCES = os.path.abspath(os.path.join(os.path.dirname(__file__), "resources"))


class TestCbFeedInfoMethods(TestCommon):
    """
    Validate the methods in the CbFeedInfo class.
    """

    def test_01a_neg_init_icon_path_invalid(self):
        """
        On initialization, detect an icon path that does not exist.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = "./foobar.png"
        try:
            CbFeedInfo(validate=False, **info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data" in err.args[0]

    def test_01b_neg_init_icon_path_data_invalid_bad_padding(self):
        """
        Verify that bad encoding for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = info['feedinfo']['icon'][:-2]
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data: Incorrect padding" in err.args[0]

    def test_01c_neg_init_icon_path_data_invalid_bad_encoding(self):
        """
        Verify that bad encoding for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = info['feedinfo']['icon'] + "%$"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data: Non-base64 digit found" in err.args[0]

    def test_02a_neg_init_icon_small_path_invalid(self):
        """
        On initialization, detect an icon_small path that does not exist.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon_small'] = "./foobar.png"
        try:
            CbFeedInfo(validate=False, **info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon_small data" in err.args[0]

    def test_02b_neg_init_icon_small_bad_padding(self):
        """
        Verify that bad encoding for the icon_small field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = info['feedinfo']['icon_small'][:-2]
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data: Incorrect padding" in err.args[0]

    def test_02c_neg_init_icon_small_bad_encoding(self):
        """
        Verify that bad encoding for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = info['feedinfo']['icon'] + "%$"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data: Non-base64 digit found" in err.args[0]

    def test_02d_init_icon_path(self):
        """
        Verify that get_data() works as expected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = os.path.join(RESOURCES, "taxii-logov2.png")
        CbFeedInfo(**info['feedinfo'])

    def test_03_get_data(self):
        """
        Verify that get_data() works as expected.
        """
        info, _ = self._load_feed_file()
        fi = CbFeedInfo(validate=False, **info['feedinfo'])
        check = fi.get_data()

        problems = []
        for key, value in check.items():
            if info['feedinfo'][key] != value:
                problems.append(f"Key `{key}` in stored data ({value}) differs from original ({info[key]})")

        if len(problems) > 0:
            mess = "\n  ".join(problems)
            self.fail(f"Validation failures:\n  {mess}")

    def test_04a_neg_validate_name_missing(self):
        """
        Verify that missing "name" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['name']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo missing required field(s): name" in err.args[0]

    def test_04b_neg_validate_display_name_missing(self):
        """
        Verify that missing "display_name" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['display_name']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo missing required field(s): display_name" in err.args[0]

    def test_04c_neg_validate_summary_missing(self):
        """
        Verify that missing "summary" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['summary']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo missing required field(s): summary" in err.args[0]

    def test_04d_neg_validate_tech_data_missing(self):
        """
        Verify that missing "tech_data" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['tech_data']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo missing required field(s): tech_data" in err.args[0]

    def test_04d_neg_validate_provider_url_missing(self):
        """
        Verify that missing "provider_url" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['provider_url']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo missing required field(s): provider_url" in err.args[0]

    def test_05a_validate_optional_category_missing(self):
        """
        Verify that missing optional "category" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['category']
        CbFeedInfo(**info['feedinfo'])

    def test_05b_validate_optional_icon_missing(self):
        """
        Verify that missing optional "icon" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['icon']
        CbFeedInfo(**info['feedinfo'])

    def test_05c_validate_optional_icon_small_missing(self):
        """
        Verify that missing optional "icon_small" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['icon_small']
        CbFeedInfo(**info['feedinfo'])

    def test_05d_validate_optional_version_missing(self):
        """
        Verify that missing optional "version" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['version']
        CbFeedInfo(**info['feedinfo'])

    def test_05e_validate_optional_provider_rating_missing(self):
        """
        Verify that missing optional "provider_rating" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['provider_rating']
        CbFeedInfo(**info['feedinfo'])

    def test_06_neg_validate_unsupported_field(self):
        """
        Verify that unsupported field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['foobar'] = "Garbage"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo includes extraneous key 'foobar'" in err.args[0]

    def test_07a_neg_validate_icon_bad_data_not_str(self):
        """
        Verify that bad data not a string or bytes is detected for icon field.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = 12345
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data: Data must be str or bytes in base64 encoding format" in \
                   err.args[0]

    def test_07b_neg_validate_icon_bad_data_not_image(self):
        """
        Verify that bad data (not jpg, png or gif) for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = base64.b64encode(bytes("This is bad data!", "utf-8")).decode('ascii')
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Supplied data does not appear to be a usable image format" in err.args[0]

    def test_07c_validate_icon_as_bytes(self):
        """
        Verify that bad data not a string or bytes is detected for icon field.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = bytes(info['feedinfo']['icon'], 'ascii')
        CbFeedInfo(**info['feedinfo'])

    def test_07d_neg_validate_icon_bad_data_unicode(self):
        """
        Verify that bad data (not jpg, png or gif) for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = bytes(info['feedinfo']['icon'], 'ascii') + b'\xea\x80\x80abcd\xde\xb4'
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon data: 'ascii' codec can't" in err.args[0]

    def test_08a_neg_validate_icon_small_bad_data_not_str(self):
        """
        Verify that bad data not a string or bytes is detected for icon_small field.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon_small'] = 12345
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert ("Unknown error reading/encoding icon_small data: Data must be str or bytes "
                    "in base64 encoding format") in err.args[0]

    def test_08b_neg_validate_icon_small_bad_data_not_image(self):
        """
        Verify that bad data (not jpg, png or gif) for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon_small'] = base64.b64encode(bytes("This is bad data!", "utf-8")).decode('ascii')
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Supplied data does not appear to be a usable image format" in err.args[0]

    def test_08c_validate_icon_small_as_bytes(self):
        """
        Verify that bad data not a string or bytes is detected for icon field.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon_small'] = bytes(info['feedinfo']['icon_small'], 'ascii')
        CbFeedInfo(**info['feedinfo'])

    def test_08d_neg_validate_icon_small_bad_data_unicode(self):
        """
        Verify that bad data (not jpg, png or gif) for the icon field is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon_small'] = bytes(info['feedinfo']['icon_small'], 'ascii') + b'\xea\x80\x80abcd\xde\xb4'
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Unknown error reading/encoding icon_small data: 'ascii' codec can't" in err.args[0]

        self.is_numeric = ["provider_rating", "version"]

    def test_09a_neg_validate_provider_rating_not_numeric(self):
        """
        Verify that provider_rating with a non-numeric value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['provider_rating'] = "foobar"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `provider_rating` must be int or float" in err.args[0]

    def test_09b_neg_validate_version_not_numeric(self):
        """
        Verify that version with a non-numeric value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['version'] = "foobar"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `version` must be int or float" in err.args[0]

    def test_10a_neg_validate_name_not_str_or_bytes(self):
        """
        Verify that name with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['name'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `name` must be str or bytes" in err.args[0]

    def test_10b_neg_validate_display_name_not_str_or_bytes(self):
        """
        Verify that display_name with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['display_name'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `display_name` must be str or bytes" in err.args[0]

    def test_10c_neg_validate_summary_not_str_or_bytes(self):
        """
        Verify that summary with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['summary'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `summary` must be str or bytes" in err.args[0]

    def test_10d_neg_validate_tech_data_not_str_or_bytes(self):
        """
        Verify that tech_data with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['tech_data'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `tech_data` must be str or bytes" in err.args[0]

    def test_10e_neg_validate_provider_url_not_str_or_bytes(self):
        """
        Verify that provider_url with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['provider_url'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `provider_url` must be str or bytes" in err.args[0]

    def test_10f_neg_validate_category_not_str_or_bytes(self):
        """
        Verify that category with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['category'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "FeedInfo field `category` must be str or bytes" in err.args[0]

        self.noemptystrings = ["name", "display_name", "summary", "tech_data", "category"]

    def test_11a_neg_validate_name_empty_string(self):
        """
        Verify that name with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['name'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The 'name' field must not be an empty string" in err.args[0]

    def test_11b_neg_validate_display_name_empty_string(self):
        """
        Verify that display_name with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['display_name'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The 'display_name' field must not be an empty string" in err.args[0]

    def test_11c_neg_validate_summary_empty_string(self):
        """
        Verify that summary with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['summary'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The 'summary' field must not be an empty string" in err.args[0]

    def test_11d_neg_validate_tech_data_empty_string(self):
        """
        Verify that tech_data with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['tech_data'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The 'tech_data' field must not be an empty string" in err.args[0]

    def test_11e_neg_validate_category_empty_string(self):
        """
        Verify that category with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['category'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "The 'category' field must not be an empty string" in err.args[0]

    def test_12_neg_validate_name_alphanumeric(self):
        """
        Verify that name with a non alphanumeric string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['name'] = "invalid_name"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeed as err:
            assert "Feed name `invalid_name` may only contain a-z, A-Z, 0-9 and must have one character" in err.args[0]
