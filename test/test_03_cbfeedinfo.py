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

    def test_00a_init_unknown_key(self):
        """
        Verify that an initialized feedinfo object only retains known keys.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['foobar'] = "should vanish"
        cfi = CbFeedInfo(**info['feedinfo'])
        assert "foobar" not in cfi.data

    def test_00b_init_unknown_key_strict(self):
        """
        Verify that an initialized feedinfo object only retains known keys.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['foobar'] = "should vanish"
        try:
            CbFeedInfo(strict=True, **info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feedinfo includes unknown field: foobar" in err.args[0]

    def test_00c_validate_unknown_key_unstrict(self):
        """
        Verify that validate with strict=False will turn off strictness in addition to validation.
        """
        info, _ = self._load_feed_file()
        cfi = CbFeedInfo(strict=True, **info['feedinfo'])
        cfi._data['foobar'] = "should vanish"
        cfi.validate(strict=False)
        assert "foobar" not in cfi.data
        assert not cfi.strict

    def test_00d_validate_unknown_key_strict(self):
        """
        Verify that validate with strict=True will turn on strictness in addition to validation.
        """
        info, _ = self._load_feed_file()
        cfi = CbFeedInfo(**info['feedinfo'])
        cfi._data['foobar'] = "should vanish"
        try:
            cfi.validate(strict=True)
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feedinfo includes unknown field: foobar" in err.args[0]
            assert cfi.strict

    def test_01a_update_unknown_key(self):
        """
        Verify that updated feedinfo data only retains known keys.
        """
        info, _ = self._load_feed_file()
        cfi = CbFeedInfo(**info['feedinfo'])
        info['feedinfo']['foobar'] = "should vanish"
        cfi.data = info['feedinfo']
        assert "foobar" not in cfi.data

    def test_01b_neg_update_unknown_key_strict(self):
        """
        Verify that updated feedinfo data only retains known keys.
        """
        info, _ = self._load_feed_file()
        cfi = CbFeedInfo(strict=True, **info['feedinfo'])
        info['feedinfo']['foobar'] = "should vanish"
        try:
            cfi.data = info['feedinfo']
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feedinfo includes unknown field: foobar" in err.args[0]

    # ----- Icon checks when data is initialized/updated ------------------------------

    # NOTE: both icon and icon_small go through the same checks for validity, so these tests are not duplicated

    def test_02a_init_icon_path(self):
        """
        Verify that a path supplied for icon is read and the contents used for the icon.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = os.path.join(RESOURCES, "taxii-logov2.png")
        cfi = CbFeedInfo(**info['feedinfo'])
        assert cfi.data['icon'] != info['feedinfo']['icon']

    def test_02b_neg_init_icon_path_invalid(self):
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

    def test_02c_neg_init_icon_path_unreadable(self):
        """
        On initialization, detect an icon path that cannot be read.
        """
        source = "./foobar.png"
        with open(source, 'w') as fp:
            fp.write("Text that won't be read")
        os.chmod(source, 0o000)

        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = source
        try:
            CbFeedInfo(validate=False, **info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Permission denied" in err.args[0]
        finally:
            os.chmod(source, 0o777)
            os.remove(source)

    def test_02d_neg_init_icon_data_invalid_bad_padding(self):
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

    def test_02e_neg_init_icon_data_invalid_bad_encoding(self):
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

    def test_02f_neg_init_icon_not_str(self):
        """
        Verify that a non-string entry for icon is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['icon'] = 12345
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "`icon` field is not a string (path or base64 data)" in err.args[0]

    # ----- validate() method testing --------------------------------------------------

    def test_03a_neg_validate_display_name_missing(self):
        """
        Verify that missing "display_name" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['display_name']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo missing required field(s): display_name" in err.args[0]

    def test_03b_neg_validate_name_missing(self):
        """
        Verify that missing "name" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['name']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo missing required field(s): name" in err.args[0]

    def test_03c_neg_validate_provider_url_missing(self):
        """
        Verify that missing "provider_url" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['provider_url']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo missing required field(s): provider_url" in err.args[0]

    def test_03d_neg_validate_summary_missing(self):
        """
        Verify that missing "summary" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['summary']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo missing required field(s): summary" in err.args[0]

    def test_03e_neg_validate_tech_data_missing(self):
        """
        Verify that missing "tech_data" is detected.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['tech_data']
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo missing required field(s): tech_data" in err.args[0]

    def test_04a_validate_optional_category_missing(self):
        """
        Verify that missing optional "category" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['category']
        cfi = CbFeedInfo(**info['feedinfo'])
        assert 'category' not in cfi.data

    def test_04b_validate_optional_icon_missing(self):
        """
        Verify that missing optional "icon" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['icon']
        cfi = CbFeedInfo(**info['feedinfo'])
        assert 'icon' not in cfi.data

    def test_04c_validate_optional_icon_small_missing(self):
        """
        Verify that missing optional "icon_small" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['icon_small']
        cfi = CbFeedInfo(**info['feedinfo'])
        assert 'icon_small' not in cfi.data

    def test_04d_validate_optional_provider_rating_missing(self):
        """
        Verify that missing optional "provider_rating" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['provider_rating']
        cfi = CbFeedInfo(**info['feedinfo'])
        assert 'provider_rating' not in cfi.data

    def test_04e_validate_optional_version_missing(self):
        """
        Verify that missing optional "version" is allowed.
        """
        info, _ = self._load_feed_file()
        del info['feedinfo']['version']
        cfi = CbFeedInfo(**info['feedinfo'])
        assert 'version' not in cfi.data

    # NOTE: both icon and icon_small go through the same checks for validity, so these tests are not duplicated

    def test_05a_neg_validate_icon_bad_data_not_image(self):
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

    def test_05b_validate_icon_not_str(self):
        """
        Verify that bad data not a string for icon field (should have been converted to base64 string)
        """
        info, _ = self._load_feed_file()
        cfi = CbFeedInfo(**info['feedinfo'])
        # noinspection PyTypeChecker
        cfi.data['icon'] = bytes(info['feedinfo']['icon'], 'ascii')
        try:
            cfi.validate()
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbIconError as err:
            assert "Icon must be string of base64 data" in err.args[0]

    def test_06a_neg_validate_provider_rating_not_numeric(self):
        """
        Verify that provider_rating with a non-numeric value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['provider_rating'] = "foobar"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `provider_rating` must be int or float" in err.args[0]

    def test_06b_neg_validate_version_not_numeric(self):
        """
        Verify that version with a non-numeric value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['version'] = "foobar"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `version` must be int or float" in err.args[0]

    def test_07a_neg_validate_category_not_str_or_bytes(self):
        """
        Verify that category with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['category'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `category` must be str or bytes" in err.args[0]

    def test_07b_neg_validate_display_name_not_str_or_bytes(self):
        """
        Verify that display_name with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['display_name'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `display_name` must be str or bytes" in err.args[0]

    def test_07c_neg_validate_name_not_str_or_bytes(self):
        """
        Verify that name with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['name'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `name` must be str or bytes" in err.args[0]

    def test_07d_neg_validate_provider_url_not_str_or_bytes(self):
        """
        Verify that provider_url with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['provider_url'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `provider_url` must be str or bytes" in err.args[0]

    def test_07e_neg_validate_summary_not_str_or_bytes(self):
        """
        Verify that summary with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['summary'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `summary` must be str or bytes" in err.args[0]

    def test_07f_neg_validate_tech_data_not_str_or_bytes(self):
        """
        Verify that tech_data with a non-string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['tech_data'] = 4
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "FeedInfo field `tech_data` must be str or bytes" in err.args[0]

    def test_08a_neg_validate_category_empty_string(self):
        """
        Verify that category with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['category'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "The 'category' field must not be an empty string" in err.args[0]

    def test_08b_neg_validate_display_name_empty_string(self):
        """
        Verify that display_name with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['display_name'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "The 'display_name' field must not be an empty string" in err.args[0]

    def test_08c_neg_validate_name_empty_string(self):
        """
        Verify that name with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['name'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "The 'name' field must not be an empty string" in err.args[0]

    def test_08d_neg_validate_summary_empty_string(self):
        """
        Verify that summary with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['summary'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "The 'summary' field must not be an empty string" in err.args[0]

    def test_08e_neg_validate_tech_data_empty_string(self):
        """
        Verify that tech_data with a empty string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['tech_data'] = ""
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "The 'tech_data' field must not be an empty string" in err.args[0]

    def test_09_neg_validate_name_alphanumeric(self):
        """
        Verify that name with a non alphanumeric string value is detected.
        """
        info, _ = self._load_feed_file()
        info['feedinfo']['name'] = "invalid_name"
        try:
            CbFeedInfo(**info['feedinfo'])
            self.fail("Did not get expected exception!")
        except cbfeeds.exceptions.CbInvalidFeedInfo as err:
            assert "Feed name `invalid_name` may only contain a-z, A-Z, 0-9 and must have one character" in err.args[0]
