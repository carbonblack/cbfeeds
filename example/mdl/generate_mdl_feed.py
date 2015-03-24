import os
import sys
import csv
import time
import shlex
import urlparse

from datetime import datetime
from datetime import timedelta

# third part lib imports
import requests

from distutils.version import StrictVersion
if StrictVersion(requests.__version__) < StrictVersion("1.2.3"):
    # only in 1.2.3+ did response objects support iteration 
    raise ImportError("requires requests >= 1.2.3")

# our imports
sys.path.insert(0, "../../")
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

DAYS_BACK = 90

def unicode_csv_reader(unicode_csv_data, dialect=csv.excel, **kwargs):
    # csv.py doesn't do Unicode; encode temporarily as UTF-8:
    csv_reader = csv.reader(utf_8_encoder(unicode_csv_data),
                            dialect=dialect, **kwargs)
    for row in csv_reader:
        # decode UTF-8 back to Unicode, cell by cell:
        yield [unicode(cell, 'utf-8') for cell in row]

def utf_8_encoder(unicode_csv_data):
    for line in unicode_csv_data:
        try:
            yield line.encode('utf-8')
        except UnicodeError:
            print "WARNING: unicode error, skipping %s" % line
            continue

def reports_from_csv(lines):
    """ takes a file-like object that is full list of CSV data from
        from malwaredomainlist.  creates a report per line """
    reports = []
    try:
        for line in unicode_csv_reader(lines):
            if len(line)== 0: continue
            try:
                rawdate, url, ip, reverse_lookup, desc, registrant, asn, _, _ = line

                #rawdate 2013/10/27_03:06
                report_date = time.strptime(rawdate, "%Y/%m/%d_%H:%M") 

                # skip any report older than DAYS_BACK
                report_datetime = datetime.fromtimestamp(time.mktime(report_date))
                start = datetime.now() - timedelta(days=DAYS_BACK)
                if report_datetime < start:
                    continue 

                #url www.slivki.com.ua/as/Ponynl.exe
                url = urlparse.urlsplit("http://%s" % url)
                host = url.netloc
                if ":" in host:
                    host = host.split(":", 1)[0]

                if len(host) <= 3:
                    print "WARNING: no domain, skipping %s" % line
                    continue

                fields = {'iocs': {
                                    "dns": [host],
                                  },
                          'timestamp': int(time.mktime(report_date)),
                          'link': "http://www.malwaredomainlist.com/mdl.php",
                          'id': 'MDL-%s-%s' % (time.strftime("%Y%m%d-%H%M", report_date), host),
                          'title': '%s found on malware domain list: "%s"' % (host, desc) + 
                                   ' IP (reverse lookup) at the time:  %s (%s)' % (ip, reverse_lookup),
                          'score': 100,
                        }

                reports.append(CbReport(**fields))

            except Exception, err:
                print "WARNING:  error parsing %s\n%s" % (line, err)
                continue
    except Exception, err:
        print err
        print line

    return reports

def create(localcsv=None):
    if localcsv:
        lines = open(localcsv, "r").readlines()
         
    else:
        r = requests.get("http://www.malwaredomainlist.com/mdlcsv.php", stream=True)
        lines = r.text.split("\r\n")
    
    reports = reports_from_csv(lines)
    feedinfo = {'name': 'mdl',
                'display_name': "Malware Domain List",
                'provider_url': "http://www.malwaredomainlist.com/mdl.php",
                'summary': "Malware Domain List is a non-commercial community project to track domains used by malware." +
                           " This feed contains the most recent 180 days of entries.",
                'tech_data': "There are no requirements to share any data to receive this feed.",
                "icon": "mdl.png",
                "icon_small": "mdl.small.jpg"
                }

    # lazy way out 
    old_cwd = os.getcwd()
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)
    bytes = feed.dump()

    os.chdir(old_cwd)

    return bytes

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print "usage: generate_mdl_feed.py [outfile] <local.csv>"
        sys.exit()
    
    outfile = sys.argv[1]
    localcsv = None 
    if len(sys.argv) > 2:
        localcsv = sys.argv[2]

    bytes = create(localcsv)
    open(outfile, "w").write(bytes)

