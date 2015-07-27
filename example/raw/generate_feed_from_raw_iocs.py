# stdlib imports
import re
import sys
import time
import urllib
import json
import optparse
import socket
import base64
import hashlib

# cb imports
sys.path.insert(0, "../../")
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

def gen_report_id(iocs):
    """
    a report id should be unique
    because generate_feed_from_raw may be run repeatedly on the same data, it should
    also be deterministic.
    this routine sorts all the indicators, then hashes in order to meet these criteria
    """
    md5 = hashlib.md5()

    # sort the iocs so that a re-order of the same set of iocs results in the same report id
    iocs.sort()

    for ioc in iocs:
        md5.update(ioc.strip())

    return md5.hexdigest()

def build_reports(options):
 
    reports = []

    ips = []
    domains = []
    md5s = []
  
    # read all of the lines (of text) from the provided
    # input file (of IOCs)
    # 
    raw_iocs = open(options.ioc_filename).readlines()
    
    # iterate over each of the lines
    # attempt to determine if each line is a suitable
    # ipv4 address, dns name, or md5
    #
    for raw_ioc in raw_iocs:
        
        # strip off any leading or trailing whitespace
        # skip any empty lines
        # 
        raw_ioc = raw_ioc.strip()
        if len(raw_ioc) == 0:
            continue
        
        try:
            # attempt to parse the line as an ipv4 address
            # 
            socket.inet_aton(raw_ioc)
            
            # parsed as an ipv4 address!
            #
            ips.append(raw_ioc)
        except Exception, e:

            # attept to parse the line as a md5 and, if that fails,
            # as a domain.  use trivial parsing
            #
            if 32 == len(raw_ioc) and \
               re.findall(r"([a-fA-F\d]{32})", raw_ioc):
                md5s.append(raw_ioc)
            elif -1 != raw_ioc.find("."):
                domains.append(raw_ioc) 

    fields = {'iocs': {
                      },
              'timestamp': int(time.mktime(time.gmtime())),
              'link': options.url,
              'title': options.report,
              'id': gen_report_id(ips + domains + md5s),
              'score': 100}
   
    if options.tags is not None: 
        fields['tags'] = options.tags.split(',')
    
    if len(ips) > 0:
        fields['iocs']['ipv4'] = ips
    if len(domains) > 0:
        fields['iocs']['dns'] = domains
    if len(md5s) > 0:
        fields['iocs']['md5'] = md5s

    reports.append(CbReport(**fields))

    return reports

def create_feed(options):
   
    # generate the required feed information fields
    # based on command-line arguments
    # 
    feedinfo = {'name': options.name,
                'display_name': options.display_name,
                'provider_url': options.url,
                'summary': options.summary,
                'tech_data': options.techdata}
   
    # if an icon was provided, encode as base64 and
    # include in the feed information
    # 
    if options.icon:
        bytes = base64.b64encode(open(options.icon).read())
        feedinfo['icon'] = bytes 
    
    # if a small icon was provided, encode as base64 and 
    # include in the feed information
    #
    if options.small_icon:
        bytes = base64.b64encode(open(options.small_icon).read())
        feedinfo['icon_small']
  
    # if a feed category was provided, include it in the feed information
    #
    if options.category:
        feedinfo['category'] = options.category
 
    # build a CbFeedInfo instance
    # this does field validation
    #    
    feedinfo = CbFeedInfo(**feedinfo)
   
    # build a list of reports (always one report in this
    # case).  the single report will include all the IOCs  
    # 
    reports = build_reports(options)
   
    # build a CbFeed instance
    # this does field validation (including on the report data)
    # 
    feed = CbFeed(feedinfo, reports)

    return feed.dump()

def _build_cli_parser():
    usage = "usage: %prog [options]"
    desc = "Convert a flat file of IOCs to a Carbon Black feed"

    parser = optparse.OptionParser(usage=usage, description=desc)
    
    parser.add_option("-n", "--name", action="store", type="string", dest="name",
                      help="Feed Name")
    parser.add_option("-d", "--displayname", action="store", type="string", dest="display_name",
                      help="Feed Display Name")
    parser.add_option("-u", "--url", action="store", type="string", dest="url",
                      help="Feed Provider URL")
    parser.add_option("-s", "--summary", action="store", type="string", dest="summary",
                      help="Feed Summary")
    parser.add_option("-t", "--techdata", action="store", type="string", dest="techdata",
                      help="Feed Technical Description")
    parser.add_option("-c", "--category", action="store", type="string", dest="category",
                      help="Feed Category")
    parser.add_option("-i", "--icon", action="store", type="string", dest="icon",
                      help="Icon File (PNG format)")
    parser.add_option("-S", "--small-icon", action="store", type="string", dest="small_icon",
                      help="Small icon file (50x50 pixels) (PNG format)")
    parser.add_option("-I", "--iocs", action="store", type="string", dest="ioc_filename",
                      help="IOC filename")
    parser.add_option("-r", "--report", action="store", type="string", dest="report",
                      help="Report Name")
    parser.add_option("-g", "--tags", action="store", type="string", dest="tags",
                      help="Optional comma-delimited report tags")

    return parser

if __name__ == "__main__":

    parser = _build_cli_parser()
    options, args = parser.parse_args(sys.argv)

    if not options.name or \
       not options.display_name or \
       not options.url or \
       not options.summary or \
       not options.techdata or \
       not options.ioc_filename or \
       not options.report:
        print "-> Missing option"
        sys.exit(0)

    print create_feed(options)
