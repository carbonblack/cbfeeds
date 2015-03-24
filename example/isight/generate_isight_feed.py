import os
import sys
import time
import json
import pprint
import isight_api 
import isight_config
import isight_helpers
import xml.etree.ElementTree as ET

score_stats = {}

# our imports
sys.path.insert(0, "../../")
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

def generate_feed_information():
    """
    return a dictionary of feed information
    this is feed 'metadata' - the description of the feed, and not the feed contents
    """
    feed = {}
    feed["name"] = "iSIGHT"
    feed["display_name"] = "iSIGHT Partners feed"
    feed["summary"] = "iSIGHT Partners provides a cyber intelligence feed"
    feed["tech_data"] = "There are no requirements to share any data with Carbon Black to receive this feed.  The underlying IOC data is provided by iSIGHT Partners"
    feed["provider_url"] = "http://www.isightpartners.com/"
    feed["icon"] = "isight.png"
    feed["icon_small"] = "isight.small.jpg"

    return CbFeedInfo(**feed)

def retrieve_report_score(report_name, api, default_score):
    """
    return a numeric score, between 1 and 100, corresponding
    with the report.  This requires a round-trip to the iSight api
    endpoint to retrieve an XML encoded report.  That report, in
    turn, includes a 'criticality' rating which we can translate
    into a numeric score.
    """

    global score_stats
   
    #print " -> looking up score for %s..." % (report_name)
    data = api.get_report(report_name, "xml")

    root = ET.fromstring(data)
    
    # @todo don't hardcode offset here, but look for named indicator?
    # @todo "intel" reports don't have a risk rating
    #
    for field in root[1]:
        if field.tag != "Field":
            continue
        if field.attrib['name'] == 'Risk Rating': 
            if score_stats.has_key(field.text.strip()):
                score_stats[field.text.strip()] = score_stats[field.text.strip()] + 1
            else:
                score_stats[field.text.strip()] = 1

            rating = field._children[0].text
            if 'HIGH' == rating:
                return 100
            elif 'MEDIUM' == rating:
                return 80
            elif 'LOW' == rating:
                return 60
            else:
                print "WARNING: can't find score for %s; using default" % report_name
                return default_score 

    if score_stats.has_key("MISSING"):
        score_stats["MISSING"] = score_stats["MISSING"] + 1
    else:
        score_stats["MISSING"] = 1

    print "WARNING: can't find score for %s; using default" % report_name
    return default_score 

def generate_reports(raw, api):
    """
    generate the reports data as a list of dictionaries.

    each list entry corresponds to a single report,
    which is a single report in the case of iSight.
    """

    reports = []

    for rawkey in raw.keys():

        entry = {}

        rawentry = raw[rawkey]
        
        entry["id"] = rawkey
        entry["title"] = rawentry["title"]
        entry["link"] = "https://mysight.isightpartners.com/report/full/%s" % (rawkey) 
        entry["timestamp"] = rawentry["report_timestamp"]
        entry["iocs"] = {}

        for rawmd5 in rawentry["md5"]:
            if not "md5" in entry["iocs"]: 
                entry["iocs"]["md5"] = []

            entry["iocs"]["md5"].append(rawmd5)

        # @todo uncomment this block to support ips
        #
        #for rawip in rawentry["ipaddr"]:
        #    if not "ipv4" in entry["iocs"]: 
        #        entry["iocs"]["ipv4"] = []
        #
        #    entry["iocs"]["ipv4"].append(rawip)

        for rawdns in rawentry["domain"]:
            if not "dns" in entry["iocs"]: 
                entry["iocs"]["dns"] = []

            entry["iocs"]["dns"].append(rawdns)

        # if we ended up with no IOCs for this report, just skip it.
        #
        if len(entry["iocs"]) == 0:
            continue

        # the score or severity is not provided as part of the iSight
        # report enumeration (their "i_and_w" or "indications and warnings"
        # api.  instead, we must retreive the report in XML format, parse the
        # report, and look for the criticality.
        #
        # Some iSIGHT reports have NO criticality rating.
        # For lack of clear obvious next steps, simply report the score as
        # 75 -- "medium high"
        #
        entry["score"] = retrieve_report_score(entry["id"], api, 75) 

        reports.append(CbReport(**entry))

    return reports

def create(config_file, existing_csv=None, reports_to_skip=[]):
    # parse the configuration file
    # this configuration file includes the keys needed to talk to the
    # iSight report server, etc.
    #
    #print "-> Parsing iSight configuration..."
    cfg = isight_config.ISightConfig(config_file)

    # instantiate a local iSight API object
    #
    #print "-> Instantiating an iSight API object..."
    api = isight_api.ISightAPI(cfg.iSightRemoteImportUrl,
                               cfg.iSightRemoteImportUsername,
                               cfg.iSightRemoteImportPassword,
                               cfg.iSightRemoteImportPublicKey,
                               cfg.iSightRemoteImportPrivateKey)

    if not existing_csv:
        # query the iSight report server for raw CSV report data
        # query 'back' the specified number of days
        #
        #print "-> Querying iSight server for last %d days of reports..." % (cfg.iSightRemoteImportDaysBack)
        #
        # @todo iSIGHT has a new-and-improved REST API which could be used instead of this legacy API
        #
        raw_report_data = api.get_i_and_w(cfg.iSightRemoteImportDaysBack)

        # save off the raw report data for future reference
        #
        #print "-> Saving iSight report data to iSight.csv..."
        f = open('iSight.csv', 'w')
        f.write(raw_report_data)
        f.close()
    else: 
        raw_report_data = open(existing_csv, "r").read()

    # convert the raw report data into something more managable
    # in particular, a list of dictionaries, with each dictionary describing a report
    # this helper routine accounts for the fact that report data is spread across
    # multiple lines of the raw CSV blob
    #
    results = isight_helpers.isight_csv_to_iocs_dict([raw_report_data])

    # set up a dictionary for basic stat tracking
    #
    stats = {'md5' : {'total' : 0, 'max' : 0},
             'ipaddr' : {'total' : 0, 'max' : 0}, 
             'domain' : {'total' : 0, 'max' : 0}}

    for report_id in results.keys():
        stats['md5']['total'] += len(results[report_id]['md5'])
        if len(results[report_id]['md5']) > stats['md5']['max']:
            stats['md5']['max'] = len(results[report_id]['md5'])
        stats['ipaddr']['total'] += len(results[report_id]['ipaddr'])
        if len(results[report_id]['ipaddr']) > stats['ipaddr']['max']:
            stats['ipaddr']['max'] = len(results[report_id]['ipaddr'])
        stats['domain']['total'] += len(results[report_id]['domain'])
        if len(results[report_id]['domain']) > stats['domain']['max']:
            stats['domain']['max'] = len(results[report_id]['domain'])
    
    #print "  -> Total Reports:                                  %d" % (len(results.keys()))
    #print "  -> ----------------------------------------------- ---"
    #print "  -> Maximum number of MD5s in one report:           %d" % (stats['md5']['max'])
    #print "  -> Total MD5s across all reports:                  %d" % (stats['md5']['total'])
    #print "  -> Maximum number of IPv4 addresses in one report: %d" % (stats['ipaddr']['max'])
    #print "  -> Total IPv4 addresses in all reports:            %d" % (stats['ipaddr']['total'])
    #print "  -> Maximum number of DNS names in one report:      %d" % (stats['domain']['max'])
    #print "  -> Total DNS names in all reports:                 %d" % (stats['domain']['total'])

    # generate the feed data from the raw iSight report data
    #
    #print "-> Generating feed data..."
    reports = generate_reports(results, api)
    
    # shim to skip entire reports
    reports = [report for report in reports if report.data['id'] not in reports_to_skip]

    # generate the feed metadata (feed information)
    # this is a static description of the feed itself
    #

    # lazy way out 
    cwd_old = os.getcwd()
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    #print "-> Generating feed metadata..."
    feedinfo = generate_feed_information()

    # write out feed document
    #
    feed = CbFeed(feedinfo, reports)

    #print "-> Writing out completed feed document..."
    return feed.dump()

    os.chdir(cwd_old)

    #print "-> Done!"

if __name__ == "__main__":
    #print "-> iSIGHT Partners Carbon Black feed generator"
    if len(sys.argv) < 3:
        print "\n   USAGE: generate_isight_feed.py <configfile> <outputfile> [existing_csv]\n"
        sys.exit(0) 
    cfg = sys.argv[1] 
    out = sys.argv[2]
    csv = None
    if len(sys.argv) == 4:
        csv = sys.arv[3]

    reports_to_skip = ["Intel-989749",]

    bytes = create(cfg, existing_csv=csv, reports_to_skip=reports_to_skip)
    open(out, "w").write(bytes)

