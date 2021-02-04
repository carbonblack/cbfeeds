# Carbon Black Feeds [![Build Status](https://travis-ci.org/carbonblack/cbfeeds.svg?branch=master)](https://travis-ci.org/carbonblack/cbfeeds) 


## License

Use of the Carbon Black Feeds API is governed by the license found in LICENSE.md.

## Overview

Carbon Black Response 4.0+ ships with support for threat intelligence feeds.  The Indicators of Compromise (IOCs) 
contained in the feeds are compared to the sensor data as it arrives on the server.  Any activity matching an 
IOC is tagged; users can search for the tags and, optionally, register for e-mail alerts.

Feeds allow Carbon Black servers to use freely available threat intelligence, proprietary customer threat data,
and provides a mechanism to feed threat indicators from on-premise analytic sources to Carbon Black for verification,
detection, visibility and analysis.

The CB Response 4.0+ server supports three types of indicators:

  * Binary MD5s
  * IPv4 addresses
  * DNS names

The CB Response 5.0+ server adds support for two new types of indicators:

  * Process Queries (Process Searches)
  * Binary Queries (Binary Searches)
  
The CB Response 6.1+ server adds support for one new type of indicator:

  * IPv6 addresses
  
The CB Response 7.0+ server adds support for one new type of indicator:

  * Binary SHA-256
  
The CB Response 7.3+ server adds support for two new types of indicator:

  * Ja3 hash
  * Ja3s hash

Please note that query IOC types have significant differences as compared to MD5s, IPv4 and IPv6 addresses, and DNS names.  Please see notes below regarding their usage.

The feed format, described in the "Feed Structure" section below, is designed for simplicity.  This should make it
easy to add support for feed data from any input source.

Example feed creation scripts are included.  See the 'Examples' section in this document for a listing of the examples.

> _**NOTE:** As of this version, python 3 is a requirement._

## Using the Carbon Black Feeds API

The Carbon Black Feeds API (CBFAPI) is found on github at:

  https://github.com/carbonblack/cbfeeds

The CBFAPI is a collection of documentation, example scripts, and a helper library to help create and validate Carbon
Black feeds.  It is not required in order to build a Carbon Black feed - a feed can be created in any language that
allows for building JSON, or even built by hand.  The feed file itself must match the feed structure, or schema, 
defined in the "Feed Structure" section below.

### Getting started with CBFAPI

#### install git as needed

    [root@localhost carbonblack]# yum install git
    ...

#### clone the github cbfeed repository:

    [root@localhost carbonblack]# git clone https://github.com/carbonblack/cbfeeds.git
    Initialized empty Git repository in /root/repos/carbonblack/cbfeeds/.git/
    remote: Reusing existing pack: 80, done.
    remote: Counting objects: 25, done.
    remote: Compressing objects: 100% (25/25), done.
    Receiving objects: 100% (105/105), 38.03 KiB | 17 KiB/s, done.
    Resolving deltas: 100% (50/50), done.
    remote: Total 105 (delta 10), reused 0 (delta 0)

#### Navigate to the newly-created cbfeeds directory

    [root@localhost carbonblack]# ls
    cbfeeds
    [root@localhost carbonblack]# cd cbfeeds/
    [root@localhost cbfeeds]# ls
    cbfeeds/  LICENSE.md               README.md         setup.py  validate_feed.py
    example/  percent_encode_query.py  requirements.txt  test.py

#### Navigate to the example directory and use the example `generate_tor_feed.py` (inside the example/tor/ directory) script to generate a feed from live tor egress IPs

    [root@localhost cbfeeds]# cd example/
    [root@localhost example]# python tor/generate_tor_feed.py example_tor_feed.feed
    [root@localhost example]# ls -l example_tor_feed.feed 
    -rw-r--r--. 1 root root 2179084 Mar 25 08:09 example_tor_feed.feed

#### Use the example `validate_feed.py` (inside the parent cbfeeds/ directory) script to validate the tor feed (or a feed of your choosing)

    [root@localhost cbfeeds]# python validate_feed.py --feedfile example/example_tor_feed.feed 
    -> Validated that file exists and is readable
    -> Validated that feed file is valid JSON
    -> Validated that the feed file includes all necessary CB elements
    -> Validated that all element values are within CB feed 

## Feed Structure

* Feed: a Carbon Black feed
  * FeedInfo: Feed metadata: name, description, etc
  * Reports: a list of report
      * Report metadata: title, id, URL
      * IOCs for this report

A feed is a JSON structure with two entries:

* feedinfo 
* reports

The `feedinfo` structure is a list of basic feed metadata.   `reports` is a list of `report` structures.  
Each `report` has report metadata and a list of IOCs.  

### feedinfo 

`feedinfo` is a JSON structure with the following entries:

| name             | status   | description | 
| ---------------- | -------- |-------------| 
| `display_name`   | REQUIRED | Display name for the user interface. | 
| `name`           | REQUIRED | Internal name; must not include spaces or special characters.  See Notes. | 
| `provider_url`   | REQUIRED | Human-consumpable link to view more information about this feed. | 
| `summary`        | REQUIRED | A short description of this feed. | 
| `tech_data`      | REQUIRED | More detailed technical description, to include data sharing requirements (if any) | 
| `category`       | _OPTIONAL_ | Category of the feed i.e. Open Source, Partner, Connector, First Party etc. |
| `icon`           | _OPTIONAL_ | A base64 encoded version of the image to use in the user interface | 
| `icon_small`     | _OPTIONAL_ | A base64 encoded version of a smaller icon | 
| `provider_rating`| _OPTIONAL_ | Provider rating for the feed. |
| `version`        | _OPTIONAL_ | Version of the feed source. |

Notes:

The 'name' field cannot not include spaces or special characters.  Typically, it should be unique per-feed on a single server.  

#### Icon

Recommended size/dpi for regular icon is 370px x 97px, 72 dpi.

#### Small Icon (icon_small)

Recommended size/dpi for small icon is 100px x 100px, 72dpi

Explanation of `category` parameters:

| Category Name | Description |
| ------------- | ----------- |
| `Carbon Black` | Intelligence based on output from host-based integrations | 
| `Carbon Black First Party` | Intelligence generated inside the Threat Intelligence Cloud by the Carbon Black Research team | 
| `Connectors` | Intelligence connectors from third party technologies Carbon Black have integrated with | 
| `Meta-feed` | Includes a theme-based aggregate of selected intelligence indicators from other feeds |
| `Partner`     | Proprietary threat intelligence provided to the Threat Intelligence Cloud via a partner agreement. | 
| `Open Source` | Open Source intelligence that is generally available to the public | 


An example `feedinfo` structure, from the `generate_tor_feed.py` script:

```
  "feedinfo": {
    "name": "tor",
    "display_name": "Tor Exit Nodes",
    "provider_url": "https://torproject.org/",
    "summary": "This feed is a list of Tor Node IP addresses, updated every 30 minutes.",
    "tech_data": "There are no requirements to share any data to receive this feed.",
    "icon": "tor.png",
    "icon_small": "tor.small.png",
    "category": "Open Source"
   }
```

### report

A `report` is a JSON structure with the following entries:

| name           | status   | description | 
| -------------- | -------- |-------------| 
| `id`           | REQUIRED | A report id, must be unique per feed `name` for the lifetime of the feed.  Must be alphanumeric (including no spaces).| 
| `iocs`         | REQUIRED | The IOCs for this report.  A match on __any__ IOC will cause the activity to be tagged with this report id.  The IOC format is described below.| 
| `link`         | REQUIRED | Human-consumbable link to information about this report.| 
| `score`        | REQUIRED | The severity of this report from -100 to 100, with 100 most critical.| 
| `timestamp`    | REQUIRED | Time this report was last updated, in seconds since epoch (GMT).  This should always be updated whenever the content of the report changes.| 
| `title`        | REQUIRED | A one-line title describing this report.| 
| `description`  | _OPTIONAL_ | A description of the report. |
| `tags`         | _OPTIONAL_ | A comma separated list of identifiers to tag the report. |

### iocs

CB Response 4.0+ ships supports four types of IOCs:

* IPv4 addresses
* domain names
* md5s

CB Response 5.0+ supports all 4.0 IOCs and adds one additional type:

* query - this contains query related to modules or events

CB Response 6.1+ supports all 5.0 IOCs and adds one additional type:

* ipv6 addresses

The CB Response 7.0+ server adds support for one new type of indicator:

  * Binary SHA-256
  
The CB Response 7.3+ server adds support for two new types of indicator:

  * Ja3 hash
  * Ja3s hash

`iocs` is a structure with one or more of these entries:

| name           | status   | description | 
| -------------- | -------- |-------------| 
| `dns`          | _OPTIONAL_ | A list of domain names| 
| `ipv4`         | _OPTIONAL_ | A list of IPv4 addresses in dotted decimal form|
| `ipv6`         | _OPTIONAL_ | A list of IPv6 addresses|
| `ja3`          | _OPTIONAL_ | A list of ja3 hashes (md5)|
| `ja3s`         | _OPTIONAL_ | A list of ja3s hashes (md5)|
| `md5`          | _OPTIONAL_ | A list of md5s|
| `query`        | _OPTIONAL_ | A query of type "events" or "modules"| 
| `sha256`       | _OPTIONAL_ | A list of sha-256s|

An example `reports` list with two `report` structures, each with one IPv4 IOC, from the example_tor.py script:

```
  "reports": [
    {
      "timestamp": 1380773388,
      "iocs": {
        "ipv4": [
          "100.2.142.8"
        ]
      },
      "link": "https://www.dan.me.uk/tornodes",
      "id": "TOR-Node-100.2.142.8",
      "title": "As of Wed Oct  2 20:09:48 2013 GMT, 100.2.142.8 has been a TOR exit for 26 days, 0:44:42. Contact: Adam Langley <xxx@xxxviolet.org>"
    },
    {
      "timestamp": 1380773388,
      "iocs": {
        "ipv4": [
          "100.4.7.69"
        ]
      },
      "link": "https://www.dan.me.uk/tornodes",
      "id": "TOR-Node-100.4.7.69",
      "title": "As of Wed Oct  2 20:09:48 2013 GMT, 100.4.7.69 has been a TOR exit for 61 days, 2:07:23. Contact: GPG KeyID: 0x1F40CBDC Jeremy <jeremy@xxxlaw.net>"
    }
  ]
```
Another example with "query" IOC:

```
"reports": 
[
    {
      "title": "Notepad processes", 
      "timestamp": 1388538906, 
      "iocs": {
        "query": [
          {
            "index_type": "events",
            "search_query": "cb.urlver=1&q=process_name%3Anotepad.exe"
          }
        ]
      }, 
      "score": 50, 
      "link": "http://www.myfeedserver/feed/report/notepad_proc",
      
      "id": "notepad_proc"
    },
    {
      "title": "Newly loaded modules", 
      "timestamp": 1388570000, 
      "iocs":
      {
        "query": [
          {
            "index_type": "modules",
            "search_query": "cb.urlver=1&q=is_executable_image%3Afalse"
          }
        ]
      }, 
      "score": 50,
       
      "link": "http://www.dxmtest1.org/02",
      "id": "new_mod_loads"
    }
]
```
## Validation criteria for "query" IOC reports
Following conditions apply for "query" IOC reports

* the "iocs" element can only contain one "query" element
* only "events" and "modules" are valid values for "index_type" element
* a report with a query CANNOT also have other IOCs

The "search_query" syntax is particularly noteworthy.  The following conditions apply for the "search_query" field:

* the "search_query" syntax is described in CB Enterprise Server Query Overview documentation
* the query itself should be prepended with a q=
* the query should be percent-encoded.  This can be accomplished in several ways, including:
  * by copying a query from the Carbon Black UI
  * by using a quoting library such as included with python in urllib.
  * by using the included percent_encode_query.py script
 
As with all feeds, it is highly recommended to provide initial validation of the feed with the included validate_feed.py script.  For any feeds that include query IOCs, it is recommended to run feed_query_validate.py in the cbapi github repo.

## Performance ramifications of "query" IOC reports

Queries IOCs impose a much higher performance cost on the CB Response Server than md5, dns, and ip IOCs.  Furthermore, the relative costs of queries can very signficantly.  As a general rule, 'events' queries are more expensive than 'modules' queries.  The use of wildcards, long paths, joined seearches, or multiple terms are also expensive.  

It is recommended that feed developers take care in constructing query IOCs and test against representative server prior to deploying in production.

## Feed Synchronization 

The CB Response server periodically synchronizes enabled feeds.  There are two types of feed synchronization:

* Incremental
* Full

Incremental synchronization updates any new reports and reports with updated timestamps.  Deleted reports and those reports which have been changed, but without a change to the report timestamp, are not synchronized.

Full synchronization accounts for all feed changes, even when the report timestamp is not changed or a report is deleted.

Full synchronization occurs less frequently than incremental synchronization.  It can be triggered manually via the web console or via the Carbon Black Client API.  Alternatively, the following practices will result in all report changes being synchronized via incremental synchronization:

* Update all report timestamps whenever there is a change to the report.  The accuracy of the timestamp is less important than the fact that the timestamp increases.
* For reports to be deleted, remove all IOCs from the report and update the timestamp rather than removing the report.
 
## Examples 

Several example scripts are included in the 'example' subdirectory.  These example scripts illustrate using the Carbon Black cbfeeds API to generate Carbon Black feeds from a variety of data sources.

| directory | name            | description | 
| --------- | --------------- | ------------|
| abuse_ch  | abuse.ch        | The Swiss security blog abuse.ch tracks C&C servers for Zeus, SpyEye and Palevo malware.|
| isight    | iSIGHT Partners | iSIGHT Partners customers can use their API key to generate a Carbon Black feed from iSIGHT Partners cyber threat intelligence.|
| mdl       | Malware Domain List | Malware Domain List is a non-commercial community project to track domains used by malware.|
| raw       | raw             | Build a Carbon Black feed from a raw list of IOCs.|
| tor       | Tor             | Provide a Carbon Black feed from a live list of Tor exit nodes provided by torproject.org| 
