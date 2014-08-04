# STIX to Cb Feed

STIX is the Structured Threat Information eXpression, developed and curated by Mitre as a serialization format to share Cyber Threat Intelligence Information.  You can find more information at http://stix.mitre.org.

The objectives of STIX are notably larger than the CB Feeds format, so a one-to-one translation is not possible.   However, for simpler STIX Package formats, it is possible to translate the STIX Package into a Carbon Black feed.

*Note*: The diversity of STIX package structures can cause the translation to have unexpected results.  Send us feedback (or a pull request!) with any recommendations or improvements surfaced by your source data!  

# stix_to_feed.py

This script requires:

* cbfeeds
* python-stix 
  * Docs: http://stix.readthedocs.org/en/latest/
  * Github: https://github.com/STIXProject/python-stix
  * PyPI: https://pypi.python.org/pypi/stix/

Given a STIX Package or a directory of STIX Packages, it will translate all suitable indicators into a Cb Feed Report.  Example:

    [root@localhost stix]$ python stix_to_feed.py -i sample_data/ -o stix.feed
    -> Including 3 observables from sample_data/command-and-control-ip-range.xml.
    -> Including 1 observables from sample_data/indicator-for-c2-ip-address.xml.
    -> Including 3 observables from sample_data/STIX_Domain_Watchlist.xml.
    -> Including 3 observables from sample_data/STIX_IP_Watchlist.xml.
    -> No suitable observables found in sample_data/STIX_Phishing_Indicator.xml; skipping.
    -> No suitable observables found in sample_data/STIX_URL_Watchlist.xml; skipping.

Suitable indicators are:

* DomainNameObjects
* AddressValueObjects
* FileObjects with MD5 Hash

Only these objects with no conditionals or Any Equals conditions are translated.

The sample packages in the sample\_data directory are collected from the STIX documentation.   This parser was also tested against the Mandiant APT1 and FireEye Poison Ivy reports.  Those results:

    [root@localhost other_data]$ python stix_to_feed.py -i sample_data/ -o stix.feed
    -> Including 2046 observables from sample_data/APT1/Appendix_D_FQDNs.xml.
    -> Including 1007 observables from sample_data/APT1/Appendix_E_MD5s.xml.
    -> No suitable observables found in sample_data/APT1/Appendix_F_SSLCertificates.xml; skipping.
    -> Including 1797 observables from sample_data/APT1/Appendix_G_IOCs_Full.xml.
    -> No suitable observables found in sample_data/APT1/Appendix_G_IOCs_No_Observables.xml; skipping.
    -> Including 1797 observables from sample_data/APT1/Appendix_G_IOCs_No_OpenIOC.xml.
    -> No suitable observables found in sample_data/APT1/Mandiant_APT1_Report.xml; skipping.
    -> Including 506 observables from sample_data/Poison Ivy/fireeye-pivy-indicators.xml.
    -> Including 506 observables from sample_data/Poison Ivy/fireeye-pivy-observables.xml.
    -> Including 506 observables from sample_data/Poison Ivy/fireeye-pivy-report-with-indicators.xml.
    -> No suitable observables found in sample_data/Poison Ivy/fireeye-pivy-report.xml; skipping.

Those packages are too large to include in the sample data, they are available from the Samples page at Mitre STIX: http://stix.mitre.org/language/version1.1/samples.html.

# Changelog

4 Aug 14 - 1.0 - initial cut

