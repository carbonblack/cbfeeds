#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################


import csv
import logging
import os
import sys
import time
import urllib.parse as urlparse
from datetime import datetime, timedelta
from distutils.version import StrictVersion
from typing import List, Optional

# third part lib imports
import requests

if StrictVersion(requests.__version__) < StrictVersion("1.2.3"):
    # only in 1.2.3+ did response objects support iteration 
    raise ImportError("requires requests >= 1.2.3")

# our imports
sys.path.insert(0, "../../")
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

# NOTE: as of 10/03/2020, the feed only returns data in the year 2009; adding functionality for ALL data
DAYS_BACK: Optional[int] = 90  # use number for days back from today, None for all data

logger = logging.getLogger(__name__)


def reports_from_csv(lines: List[str]) -> List[CbReport]:
    """
    Takes a file-like object that is full list of CSV data from rom malwaredomainlist.
    creates a report per line.
    """
    reports = []
    unique_domains = set()

    # fixing line referencing in except clause before it is actually referenced.
    line = None
    try:
        for line in lines:
            line = line.strip()  # trim spaces
            if len(line) == 0:
                continue
            try:
                rawdate, url, ip, reverse_lookup, desc, registrant, asn, _, _, _ = list(csv.reader([line]))[0]

                # rawdate 2013/10/27_03:06
                report_date = time.strptime(rawdate, "%Y/%m/%d_%H:%M")

                # skip any report older than DAYS_BACK, unless defined as None
                if DAYS_BACK is not None:
                    report_datetime = datetime.fromtimestamp(time.mktime(report_date))
                    start = datetime.now() - timedelta(days=DAYS_BACK)
                    if report_datetime < start:
                        continue

                # url www.slivki.com.ua/as/Ponynl.exe
                url = urlparse.urlsplit(f"http://{url}")
                host = url.netloc
                if ":" in host:
                    host = host.split(":", 1)[0]

                if len(host) <= 3:
                    logger.debug(f"WARNING: no domain, skipping line {line}")
                    continue

                # avoid duplicate report ids
                # CBAPI-21
                if host in unique_domains:
                    continue
                else:
                    unique_domains.add(host)

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

            except Exception as err:
                logger.warning(f"WARNING: error parsing {line}\n{err}")
    except Exception as err2:
        logger.info(f"Unexpected exception with linw `{line}:\n{err2}")

    return reports


def create(local_csv_file: str = None) -> str:
    """
    Create a feed from www.malwaredomainlist.com.

    :param local_csv_file: path to local file to use instead of remote call
    :return: feed JSON.
    """
    if local_csv_file:  # use local
        with open(local_csv_file, "r") as fp2:
            lines = fp2.readlines()
    else:  # use remote
        r = requests.get("http://www.malwaredomainlist.com/mdlcsv.php", stream=True)
        lines = r.text.split("\r\n")

    iconhome = os.path.dirname(__file__)
    reports = reports_from_csv(lines)
    feedinfo = {'name': 'mdl',
                'display_name': "Malware Domain List",
                'provider_url': "http://www.malwaredomainlist.com/mdl.php",
                'summary': "Malware Domain List is a non-commercial community project to track domains used by " +
                           "malware. This feed contains the most recent 180 days of entries.",
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': os.path.join(iconhome, "mdl.png"),
                'icon_small': os.path.join(iconhome, "mdl.small.jpg"),
                'category': "Open Source"
                }

    logger.info(f">> Feed `{feedinfo['display_name']}` generated with {len(reports)} reports")
    feedinfo = CbFeedInfo(**feedinfo)
    the_feed = CbFeed(feedinfo, reports)
    feed_json = the_feed.dump()

    return feed_json


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("usage: generate_mdl_feed.py <outfile> [local.csv]")
        sys.exit()

    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')

    outfile = sys.argv[1]
    localcsv = None
    if len(sys.argv) > 2:
        localcsv = sys.argv[2]

    feed = create(localcsv)
    with open(outfile, "w") as fp:
        fp.write(feed)
