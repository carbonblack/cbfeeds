#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

__all__ = ["CbException", "CbIconError", "CbInvalidFeed", "CbInvalidFeedInfo", "CbInvalidReport"]


# CBFeeds Exception set
class CbException(Exception):
    """CBFeeds base exception class"""
    pass


class CbIconError(CbException):
    """Exception for icon related issues"""
    pass


class CbInvalidFeed(CbException):
    """Exception for problems with overall feed structure"""
    pass


class CbInvalidFeedInfo(CbException):
    """Exception for problems with feedinfo information"""
    pass


class CbInvalidReport(CbException):
    """Exception for problems with report information"""
    pass
