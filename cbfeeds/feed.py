#  coding: utf-8
#  Carbon Black EDR Copyright © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import base64
import imghdr
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from cbfeeds import CbIconError, CbInvalidFeed, CbInvalidFeedInfo, CbInvalidReport

logger = logging.getLogger(__name__)


class CbFeedInfo(object):
    """
    Class to handle the data in the feedinfo section of a feed.
    """

    def __init__(self, validate: bool = True, strict: bool = False, **kwargs):
        """
        Initialize the class. Any keys that are not required or optional will be ignored.

        :param validate: If True, validate after initialization (default True)
        :param strict: If True, raise exception on unknown fields instead of dropping them
        :param kwargs: feedinfo data as a dict
        """
        # internal data
        self._data: Dict[str, Union[str, int, float]] = {}

        # these fields are required in every feed descriptor
        self.required = ["display_name", "name", "provider_url", "summary", "tech_data", ]

        # optional, my not be in every feed
        self.optional = ["category", "icon", "icon_small", "provider_rating", "version"]

        # these fields are expected to be numeric
        self.is_numeric = ["provider_rating", "version"]

        # these fields are strings that cannot be empty
        self.noemptystrings = ["name", "display_name", "summary", "tech_data", "category"]

        self.strict = strict

        self.data = kwargs
        if validate:
            self.validate()

    def __str__(self):
        """Return a descriptive string of the object."""
        return f"CbFeedInfo({self._data.get('name', 'unnamed')})"

    def __repr__(self):
        """Return the canonical string representation of the object."""
        return repr(self._data)

    @property
    def data(self) -> Dict[str, Union[str, int, float]]:
        """
        :return: the internally stored value
        """
        return self._data

    @data.setter
    def data(self, new_data: Dict[str, Union[str, int, float]]) -> None:
        """
        Update the internal data, ignoring unknown keys.

        :param new_data: new structure to update data with
        """
        self._data = new_data

        pruner = []
        for key in self._data.keys():
            if key not in self.required and key not in self.optional:
                if self.strict:
                    raise CbInvalidFeedInfo(f"Feedinfo includes unknown field: {key}")
                else:
                    pruner.append(key)
        for item in pruner:
            del self._data[item]
            logger.debug(f"Pruned unknown field `{item}` from feedinfo")

        def is_base64(data: str, strict: bool = False) -> Tuple[bool, Optional[str]]:
            try:
                if isinstance(data, str):
                    use_data = data
                elif isinstance(data, bytes):
                    use_data = data.decode('ascii')
                else:
                    raise CbIconError("Data must be str or bytes in base64 encoding format")
                check = base64.b64encode(base64.b64decode(use_data, validate=strict)).decode('ascii') == use_data
                return check, None
            except Exception as err2:
                return False, f"{err2}"

        # NOTE: if they are present, the icon fields could just be paths to actual data (for convenience)

        for icon_field in ["icon", "icon_small"]:
            if icon_field in self._data and self._data[icon_field] is not None and self._data[icon_field] != "":
                if not isinstance(self._data[icon_field], (str, bytes)):
                    raise CbIconError(f"`{icon_field}` field is not a string (path or base64 data)")

                # Check to see if it is base64 encodable data (no strict check)
                if is_base64(self._data[icon_field])[0]:  # looks to be valid base64, as far as we can tell
                    continue

                # Failed decoding check, check for path
                if os.path.exists(self._data[icon_field]):
                    icon_path = self._data.pop(icon_field)
                    try:
                        with open(icon_path, "rb") as icon_file:
                            self._data[icon_field] = base64.b64encode(icon_file.read()).decode('ascii')
                    except Exception as err:
                        raise CbIconError(f"Unknown error reading/encoding {icon_field} data: {err}")

                # not a path, may be data
                ok, err = is_base64(self._data[icon_field], strict=True)
                if not ok:
                    raise CbIconError(f"Unknown error reading/encoding {icon_field} data: {err}")

    # --------------------------------------------------

    def validate(self, strict: bool = None) -> None:
        """
        Perform a set of checks to validate data before we export the feed.

        :param strict: If True or False, changes srict setting of class; True raises exception on non-CB fields, False
                       prunes them
        :raises: CbInvalidFeed if there are validation problems
        """
        if strict is not None:
            if isinstance(strict, bool):
                self.strict = strict
            else:
                raise TypeError("`strict` parameter must be a boolean")
        self.data = self._data  # re-asess

        # verify that all required fields are there
        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidFeedInfo("FeedInfo missing required field(s): %s" % missing_fields)

        # check to see if icon_field is a string or bytes base64 decoded
        for icon_field in ["icon", "icon_small"]:
            if icon_field in self.data:
                try:
                    # If there's any bytes or unicode here, an exception will be thrown
                    if not isinstance(self.data[icon_field], str):
                        raise CbIconError("Icon must be string of base64 data")

                    # check data for image information
                    tf = tempfile.NamedTemporaryFile()
                    tf.write(base64.b64decode(self.data[icon_field]))
                    tf.flush()
                    what = imghdr.what(tf.name)
                    if what not in ['png', 'gif', 'jpeg']:
                        raise CbIconError(f"Supplied data does not appear to be a usable image format (is {what})")
                except TypeError as err:
                    raise CbIconError("Icon must either be path or base64 data.  \
                                            Path does not exist and base64 decode failed with: %s" % err)

        # All fields in feedinfo must be strings unless otherwise stated
        for key in self.data.keys():
            if key in self.is_numeric:
                if not isinstance(self.data[key], (int, float)):
                    raise CbInvalidFeedInfo(
                        f"FeedInfo field `{key}` must be int or float, not type {type(self.data[key])}")
            else:
                if not isinstance(self.data[key], (str, bytes)):
                    raise CbInvalidFeedInfo(
                        f"FeedInfo field `{key}` must be str or bytes, not type {type(self.data[key])}")

        # certain fields, when present, must not be empty strings
        for key in self.data.keys():
            if key in self.noemptystrings and self.data[key] == "":
                raise CbInvalidFeedInfo(f"The '{key}' field must not be an empty string")

        # validate shortname of this field is just a-z and 0-9, with at least one character
        if not self.data["name"].isalnum():
            raise CbInvalidFeedInfo(f"Feed name `{self.data['name']}` may only contain a-z, A-Z, "
                                    "0-9 and must have one character")


class CbReport(object):
    """
    Class to handle the data in the reports section of a feed.
    """

    def __init__(self, allow_negative_scores: bool = False, validate: bool = True, strict: bool = False, **kwargs):
        """
        Initialize the class.

        :param allow_negative_scores: If True, allow for negative scores
        :param validate: If True, validate
        :param strict: If True, raise exception on unknown fields instead of dropping them
        :param kwargs: actual report data
        """
        # negative scores introduced in CB 4.2
        # negative scores indicate a measure of "goodness" versus "badness"
        self.allow_negative_scores = allow_negative_scores

        # these fields are required in every report
        self.required = ["iocs", "timestamp", "link", "title", "id", "score"]

        # these fields must be of type string
        self.typestring = ["link", "title", "id", "description"]

        # these fields must be of type int
        self.typeint = ["timestamp", "score"]

        # these fields are optional
        self.optional = ["tags", "description"]

        # valid IOC types are "md5", "ipv4", "dns", "query"
        self.valid_ioc_types = ["md5", "sha256", "ipv4", "ipv6", "dns", "query", "ja3", "ja3s"]

        # valid index_type options for "query" IOC
        self.valid_query_ioc_types = ["events", "modules"]

        # valid query fields
        self.valid_query_fields = ["index_type", "search_query"]

        if "timestamp" not in kwargs:
            kwargs["timestamp"] = int(time.mktime(time.gmtime()))

        self.strict = strict
        self._rid = f"Report '" + f"{kwargs.get('id', '???')}" + "'"  # for exception identification

        self.data = kwargs
        if validate:
            self.validate()

    def __str__(self):
        """Return a descriptive string of the object."""
        return "CbReport(%s)" % (self.data.get("title", self.data.get("id", '')))

    def __repr__(self):
        """Return the canonical string representation of the object."""
        return repr(self.data)

    @property
    def data(self) -> Dict[str, Union[str, int, Dict, List]]:
        """
        :return: the internally stored value
        """
        return self._data

    @data.setter
    def data(self, new_data: Dict[str, Union[str, int, Dict, List]]) -> None:
        """
        Update the internal data, ignoring unknown keys.

        :param new_data: new structure to update data with
        """
        self._data = new_data

        pruner = []
        for key, value in new_data.items():
            if key not in self.required and key not in self.optional:
                if self.strict:
                    raise CbInvalidReport(f"Report includes unknown field: {key}")
                else:
                    pruner.append(key)

            # handle query dict
            if key == "iocs":
                if isinstance(value, Dict):
                    for key2, value2 in value.items():
                        if key2 == "query" and isinstance(value2, Dict):  # cope with bad data (for now)
                            pruner2 = []
                            for key3 in value2.keys():
                                if key3 not in self.valid_query_fields:
                                    if self.strict:
                                        raise CbInvalidReport(f"{self._rid}, field 'ioc' query includes"
                                                              f" unknown field: {key3}")
                                    else:
                                        pruner2.append(key3)
                            for item in pruner2:
                                del self._data[key][key2][item]
                                logger.debug(f"Pruned unknown query ioc field `{item}` from report")

        for item in pruner:
            del self._data[item]
            logger.debug(f"Pruned unknown field `{item}` from feedinfo")

    # --------------------------------------------------

    def validate(self, strict: bool = None) -> None:
        """
        Perform a set of checks to validate report data.

        :param strict: If True or False, changes srict setting of class; True raises exception on non-CB fields, False
                       prunes them
        :raises: CbInvalidReport if there are validation problems
        """
        if strict is not None:
            if isinstance(strict, bool):
                self.strict = strict
            else:
                raise TypeError("`strict` parameter must be a boolean")
        self.data = self._data  # re-asess

        # validate we have all required keys
        if not all([x in self.data.keys() for x in self.required]):
            missing_fields = ", ".join(set(self.required).difference(set(self.data.keys())))
            raise CbInvalidReport(f"Report missing required field(s): {missing_fields}")

        # CBAPI-36
        # verify that all fields that should be strings are strings or bytes
        for key in self.typestring:
            if key in self.data.keys():
                if not isinstance(self.data[key], (str, bytes)):
                    raise CbInvalidReport(f"{self._rid}, field '{key}', must be of type str or bytes, but seems to"
                                          f" be of type {type(self.data[key])}")

        # verify that all fields that should be ints are ints
        for key in self.typeint:
            if key in self.data.keys():
                if not isinstance(self.data[key], (int, float)):
                    raise CbInvalidReport(f"{self._rid}, field '{key}', must be an int")
                else:
                    self.data[key] = int(self.data[key])  # make sure it's int

        # validate that tags is a list of alphanumeric strings
        if "tags" in self.data.keys():
            if not isinstance(self.data["tags"], List):
                raise CbInvalidReport(f"{self._rid}, field 'tags', must be a list of str")
            for tag in self.data["tags"]:
                if not isinstance(tag, str):
                    raise CbInvalidReport(f"{self._rid}, field 'tag', has entry not a string ({tag}, type {type(tag)})")

                if tag.lower() == "event_query":  # the one exception
                    pass
                else:
                    if len(tag) > 32 or len(tag) < 1:
                        raise CbInvalidReport(f"{self._rid}, field 'tag', has an entry that is not 1-32"
                                              f" characters in length ({tag})")
                    if not str(tag).isalnum():
                        raise CbInvalidReport(
                            f"{self._rid}, field 'tag', has an entry that is not alphanumeric ({tag})")

        # validate score is integer between -100 (if so specified) or 0 and 100
        bottom = -100 if self.allow_negative_scores else 0
        if not self.allow_negative_scores and self.data["score"] < 0:
            raise CbInvalidReport(f"{self._rid}, field 'score' ({self.data['score']}), out of range {bottom} to 100")

        if self.data["score"] < -100 or self.data["score"] > 100:
            raise CbInvalidReport(f"{self._rid}, field 'score' ({self.data['score']}), out of range {bottom} to 100")

        # validate id of this report is just a-z and 0-9 and - and ., with at least one character
        if not re.match("^[a-zA-Z0-9-_.]+$", self.data["id"]):
            raise CbInvalidReport(
                f"{self._rid} (the id) is invalid and may only contain a-z, A-Z, 0-9, or one of [-_.]")

        # convenience variable for next tests
        iocs = self.data['iocs']

        # validate that there are at least one type of ioc present
        if not isinstance(iocs, Dict):
            raise CbInvalidReport(f"{self._rid}, field 'iocs', has bad format (must be dict)")

        if len(iocs.keys()) == 0:
            raise CbInvalidReport(f"{self._rid}, field 'iocs', has no entries")

        # validate there is at least one IOC for each report and each IOC entry has at least one entry
        for key, item in iocs.items():
            if key not in self.valid_ioc_types:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', unknown ioc '{key}'")

            if key.lower() == "query":
                if not isinstance(item, Dict):
                    raise CbInvalidReport(f"{self._rid}, field 'iocs', ioc '{key}', is not a dictionary")
                # NOTE: other query ioc testing below
            else:
                if not isinstance(item, List):
                    raise CbInvalidReport(f"{self._rid}, field 'iocs', ioc '{key}', is not a list of str")
                if len(item) == 0:
                    raise CbInvalidReport(f"{self._rid}, field 'iocs', ioc '{key}', must have at least 1 entry")
                for i in item:
                    if not isinstance(i, str):
                        raise CbInvalidReport(
                            f"{self._rid}, field 'iocs', ioc '{key}', has non-str entry (({i}, type {type(i)})")

        # Let us check and make sure that for "query" ioc type does not contain other types of ioc
        query_ioc = "query" in iocs.keys()
        if query_ioc:
            extras = []
            for key in iocs.keys():
                if key not in ["query"]:
                    extras.append(key)
            if len(extras) > 0:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', has extra keys: {extras}")

            iocs_query = iocs["query"]  # for cleaner code

            # validate that the index_type field exists
            if "index_type" not in iocs_query.keys():
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'query' section missing 'index_type'")

            # validate that the index_type is a valid value
            if not iocs_query.get("index_type", None) in self.valid_query_ioc_types:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'index_type' is not a known type"
                                      f" ({iocs_query.get('index_type', None)})")

            # validate that the search_query field exists
            if "search_query" not in iocs_query.keys():
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'query' section missing 'search_query'")

            # validate that the search_query field is at least minimally valid
            # in particular, we are looking for a "q=" (process) or "cb.q.????=" (binary)
            # this is by no means a complete validation, but it does provide a protection
            # against leaving the actual query unqualified
            for item in iocs_query["search_query"]:
                if "q=" not in item and "cb.q." not in item:
                    raise CbInvalidReport(f"{self._rid}, field 'iocs', 'query' has bad 'search_query': {item}")

                for kvpair in item.split('&'):
                    if len(kvpair.split('=')) != 2:
                        continue  # ignore simple items
                    qparts = kvpair.split('=')
                    if qparts[0] == 'q' or qparts[0].startswith("cb.q."):
                        self._is_valid_query(qparts[1])

        # validate md5 hashes
        for md5 in iocs.get("md5", []):
            x = re.findall(r"^([a-fA-F\d]{32})$", md5)
            if len(x) == 0:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'mp5' has invalid hash: {md5}")

        # validate ja3 hashes
        for ja3 in iocs.get("ja3", []):
            x = re.findall(r"^([a-fA-F\d]{32})$", ja3)
            if len(x) == 0:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'ja3' has invalid hash: {ja3}")

        # validate ja3s hashes
        for ja3s in iocs.get("ja3s", []):
            x = re.findall(r"^([a-fA-F\d]{32})$", ja3s)
            if len(x) == 0:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'ja3s' has invalid hash: {ja3s}")

        # validate sha256 hashes
        for sha256 in iocs.get("sha256", []):
            x = re.findall(r"^([a-fA-F\d]{64})$", sha256)
            if len(x) == 0:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'sha256' has invalid hash: {sha256}")

        # validate ipv4
        for ipv4 in iocs.get("ipv4", []):
            try:
                ipaddress.ip_address(ipv4)
            except ValueError as err:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'ipv4' value of {err}")

        # validate ipv6
        for ipv6 in iocs.get("ipv6", []):
            try:
                ipaddress.ip_address(ipv6)
            except ValueError as err:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'ipv6' value of {err}")

        # validate domains
        # NOTE: as per spec: https://datatracker.ietf.org/doc/rfc1035/?include_text=1
        for dns in iocs.get("dns", []):
            if len(dns.strip()) == 0:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'dns' is empty")
            if len(dns.strip()) > 253:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'dns' exceeds maximum size of 253 characters")

            # break into octets
            parts = dns.split('.')
            if len(parts) == 1:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'dns' value has too few octets ({dns})")

            # trailing . is valid, as per http://www.dns-sd.org/TrailingDotsInDomainNames.html
            if len(parts[-1]) == 0:
                parts = parts[:-2]  # clip it

            # spec limits dns to 127 octets, will likely never hit this due to overall length checks
            if len(parts) > 127:
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'dns' value has too many octets ({dns})")

            # parts defined as per https://datatracker.ietf.org/doc/rfc1035/?include_text=1, section 2.3.1
            # However, examples draw upon sources that provide domains that seem to break this, so we will
            # loosen the strict validation.
            for part in parts:
                x = re.findall(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?$', part)
                if len(x) == 0:
                    raise CbInvalidReport(f"{self._rid}, field 'iocs', 'dns' is invalid : {dns}")

    def _is_valid_query(self, q: str) -> None:
        """
        Make a determination as to if this is a valid query.

        :param q: query entry
        """
        # the query itself must be percent-encoded
        # verify there are only non-reserved characters present
        # no logic to detect unescaped '%' characters
        for c in q:
            if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%*()":
                raise CbInvalidReport(f"{self._rid}, field 'iocs', 'query' has unescaped non-reserved character "
                                      f"'{c}' found in query; use percent-encoding")


# --------------------------------------------------------------------------------

class CbJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for CbFeed."""

    def default(self, o):
        return o.dump()


class CbFeed(object):
    """
    Class to hold feed information.
    """

    def __init__(self, feedinfo: Union[CbFeedInfo, Dict[str, Union[str, int, float]]],
                 reports: List[Union[CbReport, Dict[str, Union[str, int, Dict, List]]]]):
        """
        Initialize the class.

        :param feedinfo: feedinfo portion of a feed, as dict or CbFeedInfo object
        :param reports: reports portion of a feed, as list of dict or list of CbReport objects
        """
        # basic sanity check!
        if not isinstance(feedinfo, (Dict, CbFeedInfo)):
            raise CbInvalidFeed("The supplied `feedinfo` parameter does not appear to be a valid dictionary"
                                f" or CbFeedInfo object (is {type(feedinfo)})")
        if not isinstance(reports, List):
            raise CbInvalidFeed(f"The supplied `reports` parameter does not appear to be a valid list"
                                f" (is {type(reports)})")
        else:
            for item in reports:
                if not isinstance(item, (Dict, CbReport)):
                    raise CbInvalidFeed(f"The `reports` parameter must be a list of dictionaries"
                                        f" or CbReport objects (saw {type(item)})")

        use_feed = feedinfo if isinstance(feedinfo, Dict) else feedinfo.data
        use_rep = [rep if isinstance(rep, Dict) else rep.data for rep in reports]

        # save raw data internally
        self.data = {'feedinfo': use_feed,
                     'reports': use_rep}

    def __repr__(self):
        """Return the canonical string representation of the object."""
        return repr(self.data)

    def __str__(self):
        """Return a descriptive string of the object."""
        return f"CbFeed({self.data.get('feedinfo', 'unknown')})"

    # --------------------------------------------------

    def validate(self, serialized_data: str = None, strict: bool = False) -> None:
        """
        Validates the feed information.

        :param serialized_data: serialized data for the feed (JSON string)
        :param strict: If True, throw exception for non-CB fields, otherwise just prune them
        """
        if not serialized_data:
            # this should be identity, but just to be safe.
            serialized_data = self.dump(validate=False)

        data = json.loads(serialized_data)

        if "feedinfo" not in data:
            raise CbInvalidFeedInfo("Feed missing 'feedinfo' data")

        if 'reports' not in data:
            raise CbInvalidFeedInfo("Feed missing 'reports' structure")

        dispname = data['feedinfo'].get('display_name', "???")

        # validate the feed info
        try:
            CbFeedInfo(strict=strict, validate=True, **data["feedinfo"])
        except Exception as err:
            raise CbInvalidFeedInfo(f"Problem with feed `{dispname}`: {err}")

        # validate each report individually
        for rep in data["reports"]:
            try:
                CbReport(strict=strict, validate=True, **rep)
            except Exception as err:
                raise CbInvalidReport(f"Problem with feed `{dispname}`, report `{rep['id']}`: {err}")

        # validate the reports as a whole
        self.validate_report_list(data["reports"])

    def dump(self, validate: bool = True, sort_keys: bool = True) -> str:
        """
        Dumps the feed data.

        :param validate: is set, validates feed before dumping
        :param sort_keys: If True, pretty it up by storing the keys
        :return: json string of feed data
        """
        if validate:
            self.validate()
        return json.dumps(self.data, cls=CbJSONEncoder, indent=2, sort_keys=sort_keys)

    def iter_iocs(self) -> Generator:
        """
        Yields all iocs in the feed.

        :return: iterator of all iocs
        """
        data = json.loads(self.dump(validate=False))
        for report in data["reports"]:
            for md5 in report.get("iocs", {}).get("md5", []):
                yield {"type": "md5", "ioc": md5, "report_id": report.get("id", "")}
            for sha256 in report.get("iocs", {}).get("sha256", []):
                yield {"type": "sha256", "ioc": sha256, "report_id": report.get("id", "")}
            for ipv4 in report.get("iocs", {}).get("ipv4", []):
                yield {"type": "ipv4", "ioc": ipv4, "report_id": report.get("id", "")}
            for ipv6 in report.get("iocs", {}).get("ipv6", []):
                yield {"type": "ipv6", "ioc": ipv6, "report_id": report.get("id", "")}
            for domain in report.get("iocs", {}).get("dns", []):
                yield {"type": "dns", "ioc": domain, "report_id": report.get("id", "")}
            for ja3 in report.get("iocs", {}).get("ja3", []):
                yield {"type": "ja3", "ioc": ja3, "report_id": report.get("id", "")}
            for ja3s in report.get("iocs", {}).get("ja3s", []):
                yield {"type": "ja3s", "ioc": ja3s, "report_id": report.get("id", "")}
            for query in report.get("iocs", {}).get("query", {}).get("search_query", {}):
                yield {"type": "query", "ioc": query, "report_id": report.get("id", "")}

    @staticmethod
    def validate_report_list(reports: List[Dict[str, Any]]) -> None:
        """
        Validates reports as a set, as compared to each report as a standalone entity.

        :param reports: list of reports
        """

        reportids = set()

        # Verify that no two reports have the same feed id -- see CBAPI-17
        for report in reports:
            if report['id'] in reportids:
                raise CbInvalidFeedInfo(f"Duplicate report id '{report['id']}'")
            reportids.add(report['id'])
