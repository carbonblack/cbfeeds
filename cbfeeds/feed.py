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

    def dump(self):
        return json.dumps(self.data, cls=CbJSONEncoder, indent=2)

    def __repr__(self):
        return repr(self.data)

    def __str__(self):
        return "CbFeed(%s)" % (self.data.get('feedinfo', "unknown"))

    def _validate(self, serialized_data=None):
        if not serialized_data:
            # this should be identity, but just to be safe.
            serialized_data = self.dump()

        data = json.loads(serialized_data) 
        if not "feedinfo" in data:
            raise CbInvalidFeed("Feed missing 'feedinfo' data")

        if not 'reports' in data:
            raise CbInvalidFeed("Feed missing 'reports' structure")

        # instantiate each object and validate.  Will throw
        # exceptions on error
        fi = CbFeedInfo(**data["feedinfo"])
        fi._validate()
        for rep in data["reports"]:
            report = CbReport(**rep)
            report._validate() 

        return True

class CbFeedInfo(object):
    def __init__(self, **kwargs):
        # these fields are required in every feed descriptor
        self.required = ["name", "display_name", "version",
                        "summary", "tech_data", "provider_url"]
        self.data = kwargs
        self.data["version"] = 1        

    def dump(self):
        self._validate()
        return self.data

    def _validate(self):
        """ a set of checks to validate data before we export the feed"""

        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidFeed("FeedInfo missing required field(s): %s" % missing_fields)

        # validate shortname of this field is just a-z
        if not self.data["name"].isalpha():
            raise CbInvalidFeed("Feed name %s may only contain a-z, A-Z" % self.data["name"])

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
    def __init__(self, **kwargs):
        # these fields are required in every feed descriptor
        self.required = ["iocs", "timestamp", "link", "title", "id", "score"]
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = int(time.mktime(time.gmtime()))

        if "score" not in kwargs:
            kwargs["score"] = 0

        self.data = kwargs

    def dump(self):
        self._validate()
        return self.data

    def _validate(self):
        # validate we have all required keys
        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidReport("Report missing required field(s): %s" % missing_fields)

        # validate score is integer between 0 and 100
        try:
            int(self.data["score"])
        except ValueError:
            raise CbInvalidReport("Non-integer score %s in report %s: %s" % (self.data["score"], self.data["id"], repr(self.data)))
        
        if self.data["score"] < 0 or self.data["score"] > 100:
            raise CbInvalidReport("Score %s out of range 0-100 in report %s: %s" % (self.data["score"], self.data["id"], repr(self.data)))

        # validate there is at least one IOC for each report and each IOC entry has at least one entry
        if not all([len(self.data["iocs"][ioc]) >= 1 for ioc in self.data['iocs']]):
            raise CbInvalidReport("Report IOC list with zero length in report %s: %s" % (self.data["id"], repr(self.data)))

        # validate IOC contents
        iocs = self.data['iocs']

        # validate all md5 fields are 32 characters and just alphanumeric
        if not all([(len(md5) == 32 and md5.isalnum()) for md5 in iocs.get("md5", [])]):
            raise CbInvalidReport("Malformed md5 in IOC list for report %s: %s" % (self.data["id"], repr(self.data)))

        # validate all IPv4 fields pass socket.inet_ntoa()
        import socket
        try:
            [socket.inet_aton(ip) for ip in iocs.get("ipv4", [])]
        except socket.error:
            raise CbInvalidReport("Malformed IPv4 addr in IOC list for report %s: %s" % (self.data["id"], repr(self.data)))

        # validate all lowercased domains have just A-Z, a-z, 0-9, . and -
        import string
        # 63 chars allowed in dns, plus "."
        allowed_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-" + "."
        for domain in iocs.get("dns", []):
            if not all([c in allowed_chars for c in domain]):
                raise CbInvalidReport("Malformed domain name in IOC list for report %s: %s" % (self.data["id"], repr(self.data)))

        return True

    def __str__(self):
        return "CbReport(%s)" % (self.data.get("title", self.data.get("id", '') ) )

    def __repr__(self):
        return repr(self.data)
