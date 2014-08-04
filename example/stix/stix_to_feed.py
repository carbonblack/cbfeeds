import os
import sys
import code
import time
import optparse

from cbfeeds import CbReport
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

try:
    from stix.core import STIXPackage
    from stix.utils.parser import EntityParser, UnsupportedVersionError
    from cybox.bindings.file_object import FileObjectType
    from cybox.bindings.domain_name_object import DomainNameObjectType
    from cybox.bindings.address_object import AddressObjectType
except ImportError:
    print "Error importing required libraries.  Requires python-stix library.  See https://stix.mitre.org/"
    sys.exit(-1)

def merge(d1, d2):
    """ given two dictionaries, return a single dictionary
        that merges the two.   
    """

    result = d1
    if not d2: return result
    for k in d2:
        if k in result:
            result[k].extend(d2[k])
        else:
            result[k] = d2[k]
    return result

def no_conditionals(obj):
    """ return true only if:
        - object has no conditionals applied or
        - conditionals are jsut "Any Equals"
    """
    # if they're not on the object...
    if not hasattr(obj, "apply_condition") or not hasattr(obj, "condition"):
        return True

    # ...or if they're not defined...
    if not obj.apply_condition or not obj.condition:
        return True

    # ... or if they're defined and any equals...
    if obj.apply_condition.lower() == "any" and \
       obj.condition.lower() == "equals":
        return True

    return False

def parse_File(file_obj):
    """ parse a FileObjectType and return a list of md5s
        if they exist and not subject to any conditionals. """

    if not hasattr(file_obj, "Hashes") or not hasattr(file_obj.Hashes, "Hash"):
        return

    iocs = {}
    iocs['md5'] = []
    for h in file_obj.Hashes.Hash:
        if not hasattr(h, "Type"): 
            continue

        # only get md5s that are true if any are present.  if not specified, assume so.
        if no_conditionals(h.Type) and \
           (h.Type.valueOf_ and h.Type.valueOf_.lower() == "md5"):

            md5s = h.Simple_Hash_Value
            iocs['md5'].extend(md5s.valueOf_.split(md5s.delimiter))
    return iocs

def parse_observable(observable):
    """ for each observable, if it's of a supported type, 
        the parse out the values and return. """

    obj = observable.to_obj()
    if not obj or not hasattr(obj, "Object") or not hasattr(obj.Object, "Properties"): return
    prop = obj.Object.Properties

    iocs = {}

    if type(prop) == AddressObjectType:
        ips = prop.Address_Value
        if no_conditionals(ips):
            iocs['ipv4'] = ips.valueOf_.split(ips.delimiter)

    elif type(prop) == DomainNameObjectType:
        domains = prop.Value
        if no_conditionals(domains):
            iocs['dns'] = domains.valueOf_.split(domains.delimiter)
    
    elif type(prop) == FileObjectType:
        merge(iocs, parse_File(prop))

    return iocs

def parse_observables(observables):
    """ iterate over the set of observables, parse out
        visibile indicators and return a dictionary of 
        iocs present and suitable for feed inclusion. """

    iocs = {}
    for observable in observables:
        try:
            merge(iocs, parse_observable(observable))
        except Exception, err:
            print "-> Unexpected error parsing observable: %s; continuing." % err

    return iocs

def build_report(fname):
    """ parse the provided STIX package and create a 
        CB Feed Report that includes all suitable observables
        as CB IOCs """

    # The python STIX libs are pedantic about document versions.  See
    # https://github.com/STIXProject/python-stix/issues/124
    # parser = EntityParser()
    # pkg = parser.parse_xml(fname, check_version=False)
    pkg = STIXPackage.from_xml(fname)

    iocs = {}
    if pkg.observables:
       iocs = parse_observables(pkg.observables.observables)

    if pkg.indicators:
        for indicator in pkg.indicators:
            iocs = merge(iocs, parse_observables(indicator.observables))

    ts = time.mktime(pkg.timestamp.timetuple()) if pkg.timestamp else int(time.mktime(time.gmtime()))
    fields = {'iocs': iocs,
               'score': 100,  # does STIX have a severity field?
               'timestamp': ts,
               'link': 'http://stix.mitre.org',
               'id': pkg.id_,
               'title': pkg.stix_header.title,
            }

    if len(iocs.keys()) == 0 or all(len(iocs[k]) == 0 for k in iocs):
        print "-> No suitable observables found in %s; skipping." % fname
        return None

    print "-> Including %s observables from %s." % (sum(len(iocs[k]) for k in iocs), fname)
    return CbReport(**fields)

def build_cli_parser():
    """
    generate OptionParser to handle command line switches
    """

    usage = "usage: %prog [options]"
    desc = "Best-effort conversion of one of more STIX Packages into a CB Feed"

    parser = optparse.OptionParser(usage=usage, description=desc)

    parser.add_option("-i", "--input", action="store", default=None, type="string", dest="input",
                      help="STIX Package(s) to process.  If a directory, will recursively process all .xml")
    parser.add_option("-o", "--output", action="store", default=None, type="string", dest="output",
                      help="CB Feed output filename")

    return parser

def build_reports(input_source):
    """ given an input file or directory, 
        build a list of Cb Feed Reports.

        This structure chooses to have one 
        report per STIX Package, with all 
        suitable observables associated.

        Based on your STIX Package structure,
        you may prefer a different arrangement.
    """

    reports = []
    if os.path.isfile(input_source):
        reports.append(build_report(input_source))
    else:
        for root, dirs, files in os.walk(input_source):
            for f in files:
                if not f.endswith("xml"): continue
                try:
                    rep = build_report(os.path.join(root, f))
                    if rep: reports.append(rep)
                except UnsupportedVersionError, err:
                    print "-> Skipping %s\n    UnsupportedVersionError: %s\n    see https://github.com/STIXProject/python-stix/issues/124" % (f, err)
                except Exception, err:
                    print "-> Unexpected error parsing %s: %s; skipping." % (f, err)
                    

    return reports

def create(input_source):

    reports = build_reports(input_source)

    # ****************************
    # TODO - you probably want to change these values to reflect your 
    # local input source
    feedinfo = {'name': 'stiximport',
                'display_name': "STIX Package Import",
                'provider_url': 'http://stix.mitre.org',
                'summary': "This feed was imported from stix package(s) at %s" % input_source,
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': 'images/stix.gif'
                }

    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)
    return feed.dump()

if __name__ == "__main__":
    parser = build_cli_parser()
    options, args = parser.parse_args(sys.argv)
    if not options.input or not options.output:
        print "-> Must specify and input file/directory and output filename"
        sys.exit(-1)

    bytes = create(options.input)
    open(options.output, "w").write(bytes)
    
