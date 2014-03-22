import os
import json
import base64

from cbfeeds import CbInvalidReport
from cbfeeds import CbIconError
from cbfeeds import CbInvalidFeed

class CbJSONEncoder(json.JSONEncoder):
    def default(self, o):
        return o.dump()

class CbFeed(object):
    def __init__(self, feedinfo, reports):
        self.data = {'feedinfo': feedinfo,
                     'reports': reports}

    def dump(self, validate=True):
        if validate:
            self.validate()
        return json.dumps(self.data, cls=CbJSONEncoder, indent=2)

    def __repr__(self):
        return repr(self.data)

    def __str__(self):
        return "CbFeed(%s)" % (self.data.get('feedinfo', "unknown"))

    def validate(self, pedantic=False, serialized_data=None):
        if not serialized_data:
            # this should be identity, but just to be safe.
            serialized_data = self.dump(validate=False)

        data = json.loads(serialized_data) 
        if not "feedinfo" in data:
            raise CbInvalidFeed("Feed missing 'feedinfo' data")

        if not 'reports' in data:
            raise CbInvalidFeed("Feed missing 'reports' structure")

        # instantiate each object and validate.  Will throw
        # exceptions on error
        fi = CbFeedInfo(**data["feedinfo"])
        fi.validate(pedantic=pedantic)
        for rep in data["reports"]:
            report = CbReport(**rep)
            report.validate(pedantic=pedantic) 

        return True

class CbFeedInfo(object):
    def __init__(self, **kwargs):
        # these fields are required in every feed descriptor
        self.required = ["name", "display_name", "version",
                        "summary", "tech_data", "provider_url"]
        self.data = kwargs
        self.data["version"] = 1        

    def dump(self):
        self.validate()
        return self.data

    def validate(self, pedantic=False):
        """ a set of checks to validate data before we export the feed"""

        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidFeed("FeedInfo missing required field(s): %s" % missing_fields)

        # validate shortname of this field is just a-z and 0-9, with at least one character
        if not self.data["name"].isalnum():
            raise CbInvalidFeed("Feed name %s may only contain a-z, A-Z, 0-9 and must have one character" % self.data["name"])

        # if icon exists and points to a file, grab the bytes
        # and base64 them
        if "icon" in self.data and os.path.exists(self.data["icon"]):
            # TODO - enforce size restrictions? dimensions?  orientation?
            # raise CbIconError("...")

            icon_path = self.data.pop("icon")
            try:
                self.data["icon"] = base64.b64encode(open(icon_path, "r").read())
            except Exception, err:
                raise CbIconError("Unknown error reading/encoding icon data: %s" % err)
        # otherwise, double-check it's valid base64
        elif "icon" in self.data: 
            try:
                base64.b64decode(self.data["icon"])
            except TypeError, err:
                raise CbIconError("Icon must either be path or base64 data.  \
                                    Path does not exist and base64 decode failed with: %s" % err)

        return True

    def __str__(self):
        return "CbFeed(%s)" % (self.data.get("name", "unnamed"))

    def __repr__(self):
        return repr(self.data)

class CbReport(object):
    def __init__(self, allow_negative_scores=False, **kwargs):
        
        # negative scores introduced in CB 4.2
        self.allow_negative_scores=allow_negative_scores
        
        # these fields are required in every report descriptor
        self.required = ["iocs", "timestamp", "link", "title", "id", "score"]
        
        # valid IOC types are "md5", "ipv4", "dns"
        self.valid_ioc_types = ["md5", "ipv4", "dns"]

        if "timestamp" not in kwargs:
            kwargs["timestamp"] = int(time.mktime(time.gmtime()))

        self.data = kwargs

    def dump(self):
        self.validate()
        return self.data

    def validate(self, pedantic=False):

        # validate we have all required keys
        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidReport("Report missing required field(s): %s" % missing_fields)

        # (pedantically) validate that no extra keys are present
        if pedantic and len(self.data.keys()) > len(self.required):
            raise CbInvalidReport("Report contains extra keys: %s" % (set(self.data.keys()) - set(self.required)))

        # validate score is integer between -100 (if so specified) or 0 and 100
        try:
            int(self.data["score"])
        except ValueError:
            raise CbInvalidReport("Report has non-integer score %s in report %s" % (self.data["score"], self.data["id"]))
        
        if self.data["score"] < -100 or self.data["score"] > 100:
            raise CbInvalidReport("Report score %s out of range -100 to 100 in report %s" % (self.data["score"], self.data["id"]))

        if not self.allow_negative_scores and self.data["score"] < 0:
            raise CbInvalidReport("Report score %s out of range 0 to 100 in report %s" % (self.data["score"], self.data["id"]))

        # validate there is at least one IOC for each report and each IOC entry has at least one entry
        if not all([len(self.data["iocs"][ioc]) >= 1 for ioc in self.data['iocs']]):
            raise CbInvalidReport("Report IOC list with zero length in report %s" % (self.data["id"]))

        # convenience variable 
        iocs = self.data['iocs']

        # validate that there are at least one type of ioc present
        if len(iocs.keys()) == 0:
            raise CbInvalidReport("Report with no IOCs in report %s" % (self.data["id"])) 

        # (pedantically) validate that no extra keys are present
        if pedantic and len(set(iocs.keys()) - set(self.valid_ioc_types)) > 0:
            raise CbInvalidReport("Report IOCs section contains extra keys: %s" % (set(iocs.keys()) - set(self.valid_ioc_types)))
        
        # validate all md5 fields are 32 characters and just alphanumeric
        if not all([(len(md5) == 32 and md5.isalnum()) for md5 in iocs.get("md5", [])]):
            raise CbInvalidReport("Malformed md5 in IOC list for report %s" % (self.data["id"]))

        # validate all IPv4 fields pass socket.inet_ntoa()
        import socket
        try:
            [socket.inet_aton(ip) for ip in iocs.get("ipv4", [])]
        except socket.error:
            raise CbInvalidReport("Malformed IPv4 addr in IOC list for report %s" % (self.data["id"]))

        # validate all lowercased domains have just A-Z, a-z, 0-9, . and -
        import string
        # 255 chars allowed in dns; all must be alphanumeric, -, .
        allowed_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-" + "."
        for domain in iocs.get("dns", []):
            if not all([c in allowed_chars for c in domain]):
                raise CbInvalidReport("Malformed domain name in IOC list for report %s" % (self.data["id"]))

        return True

    def __str__(self):
        return "CbReport(%s)" % (self.data.get("title", self.data.get("id", '') ) )

    def __repr__(self):
        return repr(self.data)
