# stdlib imports
import time
from HTMLParser import HTMLParser
from datetime import timedelta

# third part lib imports
import requests

# our imports
from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

def get_tor_nodes():
    r = requests.get("https://www.dan.me.uk/tornodes")
    lines = r.text.split("\n")
    try:
        # in his raw source, Dan brackets the data with these comments
        start = lines.index("<!-- __BEGIN_TOR_NODE_LIST__ //-->")
        end = lines.index("<!-- __END_TOR_NODE_LIST__ //-->")
    except ValueError:
        raise Exception("start/end sentinels not found in Dan's list.")

    nodes = [] 
    h = HTMLParser()
    for line in lines[start+1:end]:
        try: 
            #     <ip>|<name>|<router-port>|<directory-port>|<flags>|<uptime>|<version>|<contactinfo><br />
            line = line.replace("<br />", "")  # strip the trailing <br>. this is a little brittle... ?
            line = h.unescape(line)

            ip,name,_,_,flags,uptime,ver,contact = line.split("|", 7)
            nodes.append({'ip': ip, 
                          'name': name,
                          'flags': flags,
                          'uptime': int(uptime),
                          'contact': contact})
        except Exception, err:
            print "%s while parsing: %s" % (err, line)

    return nodes

def build_reports(nodes):
    # TODO - this is one "report" per TOR node IP.  Not ideal.
    reports = []
    for node in nodes: 
        timestr = str(timedelta(seconds=node['uptime']))
        fields = {'iocs': {
                            'ipv4': [node['ip'], ]
                          }, 
                  'date': int(time.mktime(time.gmtime())),
                  'link': 'https://www.dan.me.uk/tornodes',
                  'id':   "TOR-Node-%s" % node['ip'],
                  'title':"As of %s GMT, %s has been a TOR exit for %s. Contact: %s" % (time.asctime(time.gmtime()), 
                            node['ip'], timestr, node['contact']) }
        reports.append(CbReport(**fields))
    return reports

if __name__ == "__main__":
    nodes = get_tor_nodes()
    reports = build_reports(nodes)
    
    feedinfo = {'name': 'tor',
                'display_name': "Tor Exit Nodes",
                'provider_url': 'http://www.dan.me.uk',
                'summary': "This feed is a list of Tor Node IP addresses, updated every 30 minutes.",
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': '/root/tor.png'}
            
    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)
    open("tor", "w").write(feed.dump()) 
