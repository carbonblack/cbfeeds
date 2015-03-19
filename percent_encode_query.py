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
    cmd_parser.add_option("-n", "--no-prepend", action="store_false", default=True, dest="prepend",
                          help="Do NOT prepend \"q=\" and \"cb.urlver=1\" when not found in the query specified with \"--query\"") 
    return cmd_parser

def is_query_complete(query):
    """
    returns indication as to if query includes a q=, cb.q=, or cb.fq
    """
    if query.startswith("cb.urlver="):
        return True
    if query.startswith("q=") or \
       query.startswith("cb.q=") or \
       query.startswith("cb.fq="):
        return True
    return False

if __name__ == "__main__":

    parser = build_cli_parser()
    options, args = parser.parse_args(sys.argv)

    if not options.query:
        print "-> Must specify a query to encode; use the -q switch or --help for usage"
        sys.exit(0)
 
    print options.query
    print

    # unless overridden by operator, prepend a cb.urlver=1&q= to the query if 
    # if does not already exist.  this makes it possible for customer to copy and
    # paste query from CB UI, pass through this script, and add to a feed
    #
    # see CBAPI-7
    #
    if options.prepend and not is_query_complete(options.query):
        print "cb.urlver=1&q=" + urllib.quote(options.query)  
    else:
        print urllib.quote(options.query)
