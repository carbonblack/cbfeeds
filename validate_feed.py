import re
import sys
import time
import urllib
import json
import optparse
import socket
import base64
import cbfeeds

def _build_cli_parser():
    usage = "usage: %prog [options]"
    desc = "Convert a flat file of IOCs to a Carbon Black feed"

    parser = optparse.OptionParser(usage=usage, description=desc)
    
    parser.add_option("-f", "--feedfile", action="store", type="string", dest="feed_filename",
                      help="Feed Filename to validate")

    return parser

def validate_file(feed_filename):
    """
    validate that the file exists and is readable
    """
    f = open(feed_filename)
    contents = f.read()
    return contents

def validate_json(contents):
    """
    validate that the file is well-formed JSON
    """
    return json.loads(contents)

def validate_feed(feed):
    """
    validate that the file is valid as compared to the CB feeds schema
    """
     
    # verify that we have both of the required feedinfo and reports elements
    #
    if not feed.has_key("feedinfo"):
        raise Exception("No 'feedinfo' element found!")
    if not feed.has_key("reports"):
        raise Exception("No 'reports' element found!")

    # set up the cbfeed object
    #
    feed = cbfeeds.CbFeed(feed["feedinfo"], feed["reports"])

    # validate the feed
    # this validates that all required fields are present, and that
    #   all required values are within valid ranges
    #
    feed.validate(pedantic=False) 
    
    return feed

if __name__ == "__main__":

    parser = _build_cli_parser()
    options, args = parser.parse_args(sys.argv)

    if not options.feed_filename:
        print "-> Must specify a feed filename to validate"
        sys.exit(0)

    try:
        contents = validate_file(options.feed_filename)
        print "-> Validated that file exists and is readable"
    except Exception, e:
        print "-> Unable to validate that file exists and is readable"
        print "-> Details:"
        print
        print e
        sys.exit(0)

    try:
        feed = validate_json(contents)
        print "-> Validated that feed file is valid JSON"
    except Exception, e:
        print "-> Unable to validate that file is valid JSON"
        print "-> Details:"
        print
        print e
        sys.exit(0)

    try:
        feed = validate_feed(feed)
        print "-> Validated that the feed file includes all necessary CB elements"
        print "-> Validated that all element values are within CB feed requirements"
    except Exception, e:
        print "-> Unable to validate that the file is a valid CB feed"
        print "-> Details:"
        print
        print e
        sys.exit(0)

    try:
        feed.validate(pedantic=True)
        print "-> Validated that the feed includes no non-CB elements"
        print
    except Exception, e:
        print "-> Unable to validate that the feed includes no non-CB elements"
        print "-> Details:"
        print 
        print e
        sys.exit(0)
