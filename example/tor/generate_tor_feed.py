# stdlib imports
import os
import sys
import time
import urllib
import json

# third part lib imports

# our imports
sys.path.insert(0, "../../")
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo


def get_tor_nodes():
    nodes = []
    url = "https://onionoo.torproject.org/details?type=relay&running=true"
    jsonurl = urllib.urlopen(url)
    text = json.loads(jsonurl.read())
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
        except Exception, err:
            print "%s while parsing: %s" % (err, entry)
    return nodes


def build_reports(nodes):
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


def create():
    nodes = get_tor_nodes()
    reports = build_reports(nodes)

    feedinfo = {'name': 'tor',
                'display_name': "Tor Exit Nodes",
                'provider_url': 'https://www.torproject.org/',
                'summary': "This feed is a list of Tor Node IP addresses, updated every 30 minutes.",
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': 'tor.png',
                'icon_small': 'tor.small.jpg',
                'category': 'Open Source'}

    # lazy way out to get right icon path.  sorry.
    old_cwd = os.getcwd()
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)
    created_feed = feed.dump()

    os.chdir(old_cwd)

    return created_feed

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: %s [outfile]" % sys.argv[0]
        sys.exit(0)
    bytes = create()
    open(sys.argv[1], "w").write(bytes)
