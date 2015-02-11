import sys
import urllib
import optparse

def build_cli_parser():
    """
    generate OptionParser to handle command line switches
    """

    usage = "usage: %prog [options]"
    desc = "Encode, using percent encoding, a Carbon Black query"

    cmd_parser = optparse.OptionParser(usage=usage, description=desc)

    cmd_parser.add_option("-q", "--query", action="store", type="string", dest="query",
                          help="Query to encode")

    return cmd_parser

if __name__ == "__main__":

    parser = build_cli_parser()
    options, args = parser.parse_args(sys.argv)

    if not options.query:
        print "-> Must specify a query to encode; use the -q switch or --help for usage"
        sys.exit(0)

    print urllib.quote(options.query)
