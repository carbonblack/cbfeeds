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
            raise CbInvalidFeed("Feed missing required field(s): %s" % missing_fields)

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
        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidReport("Report missing required field(s): %s" % missing_fields)

    def __str__(self):
        return "CbReport(%s)" % (self.data.get("title", self.data.get("id", '') ) )

    def __repr__(self):
        return repr(self.data)
