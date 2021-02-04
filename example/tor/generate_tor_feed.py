# stdlib imports
import logging
import os
import sys
import time
from typing import Dict, List

import requests

#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

# third part lib imports

# our imports
sys.path.insert(0, "../../")
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

logger = logging.getLogger(__name__)


def get_tor_nodes() -> List[Dict]:
    """
    Read the remote source and return the tor node information.
    :return: list of node info
    """
    nodes = []
    url = "https://onionoo.torproject.org/details?type=relay&running=true"
    jsonurl = requests.get(url)
    text = jsonurl.json()
    for entry in text['relays']:
        try:
            for address in entry['or_addresses']:
                # IPv4 addresses are ip:port, IPv6 addresses are [ip]:port:
                # "or_addresses":["80.101.115.170:5061","[2001:980:3b4f:1:240:caff:fe8d:f02c]:5061"],
                # process only IPv4 addresses for now
                if address.count(':') == 1:
                    # All IPv4 addresses will end up here.
                    ipv4, port = address.split(':')
                    nodes.append({'ip': ipv4,
                                  'name': entry['nickname'],
                                  'port': port,
                                  'firstseen': entry['first_seen'],
                                  'lastseen': entry['last_seen'],
                                  'contact': entry.get("contact", "none")})
        except Exception as err:
            logger.warning(f"{err} while parsing: {entry}")
    return nodes


def build_reports(nodes: List[Dict]) -> List[CbReport]:
    """
    Convert tor nodes to reports.

    :param nodes: list of tor nodes
    :return: list of reports
    """
    # TODO - this is one "report" per TOR node IP.  Not ideal.
    reports = []
    unique_ips = set()
    for node in nodes:
        # avoid duplicated reports
        # CBAPI-22
        if node['ip'] in unique_ips:
            continue
        else:
            unique_ips.add(node['ip'])

        fields = {'iocs': {
            'ipv4': [node['ip'], ]
        },
            'score': 0,
            'timestamp': int(time.mktime(time.gmtime())),
            'link': 'http://www.torproject.org',
            'id': "TOR-Node-%s" % node['ip'],
            'title': "%s has been a TOR exit node since %s and was last seen %s on port %s. Contact: %s"
                     % (node['ip'], node['firstseen'], node['lastseen'], node['port'], node['contact'])}
        reports.append(CbReport(**fields))

    return reports


def create() -> str:
    """
    Create tor feed.

    :return: feed info as JSON string
    """
    nodes = get_tor_nodes()
    reports = build_reports(nodes)

    iconhome = os.path.dirname(__file__)

    feedinfo = {'name': 'tor',
                'display_name': "Tor Exit Nodes",
                'provider_url': 'https://www.torproject.org/',
                'summary': "This feed is a list of Tor Node IP addresses, updated every 30 minutes.",
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': os.path.join(iconhome, 'tor.png'),
                'icon_small': os.path.join(iconhome, 'tor.small.jpg'),
                'category': 'Open Source',
                }

    logger.info(f">> Feed `{feedinfo['display_name']}` generated with {len(reports)} reports")

    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)
    created_feed = feed.dump()

    return created_feed


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s [outfile]" % sys.argv[0])
        sys.exit(0)

    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')

    info = create()
    with open(sys.argv[1], "w") as fp2:
        fp2.write(info)
