# Carbon Black Alliance Feeds

## Table of contents

TODO

## Overview

Carbon Black 4.0+ ships with support for arbitrary threat intelligence feeds.  The Indicators of Compromise (IOCs) 
contained in the feeds are compared to the sensor data as it arrives as the server.  Any activity matching an 
IOC is tagged; users can search for the tags and, optionally, sign up for immediate e-mail alerts.

This allows every Carbon Black user to use of freely available threat data with zero friction.  It also allows
users to write their own feeds, to leverage IOCs not available through the Carbon Black Alliance feeds.

## Feed structure

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

| name  | status | description | 
| ----- | -------|-------------| 
| `name`         | REQUIRED | internal name, must be unique per Carbon Black server. | 
| `display_name` | REQUIRED | Display name for user interfaces | 
| `provider_url` | REQUIRED | Link to view more information about this feed. | 
| `summary`      | REQUIRED | A short description of this feed. | 
| `tech_data`    | REQUIRED | More detailed technical description, usually details data sent to other systems. (if any) | 
| `icon`         | OPTIONAL | A base64 encoded version of the image to use in the user interface | 

An example `feedinfo` structure, from the example_tor.py script:

```
  "feedinfo": {
    "provider_url": "http://www.dan.me.uk",
    "display_name": "Tor Exit Nodes",
    "name": "tor",
    "tech_data": "There are no requirements to share any data to receive this feed.",
    "summary": "This feed is a list of Tor Node IP addresses, updated every 30 minutes.",
    "version": 1,
    "icon": "...."
   }
```

### report

A `report` is a JSON structure with the following entries:

| name  | status | description | 
| ----- | -------|-------------| 
| `date`         | REQUIRED | Time this report was last updated, in seconds since epoch. | 
| `id`           | REQUIRED | A report id, must be unique per feed `name` for the lifetime of the feed. | 
| `link`         | REQUIRED | Link to view more information about this report. | 
| `title`        | REQUIRED | A one-line title describing this report. | 
| `iocs`         | REQUIRED | The IOCs for this report.  A match on __any__ IOC will cause the activity to be tagged with this report | 

### iocs

CB 4.0 ships with feeds version `1` and supports three kinds of IOCs:

* IPv4 addresses
* domain names
* md5s

`iocs` is a structure with one or more of these entries:

| name  | status | description | 
| ----- | -------|-------------| 
| `ipv4`         | OPTIONAL | A list of IPv4 addresses in dotted decimal form | 
| `dns`          | OPTIONAL | A list of domain names | 
| `md5`          | OPTIONAL | A list of md5s | 

An example `reports` list with two `report` structures, each with one IPv4 IOC, from the example_tor.py script:

```
  "reports": [
    {
      "date": 1380773388,
      "iocs": {
        "ipv4": [
          "100.2.142.8"
        ]
      },
      "link": "https://www.dan.me.uk/tornodes",
      "id": "TOR-Node-100.2.142.8",
      "title": "As of Wed Oct  2 20:09:48 2013 GMT, 100.2.142.8 has been a TOR exit for 26 days, 0:44:42. Contact: Adam Langley <agl@imperialviolet.org>"
    },
    {
      "date": 1380773388,
      "iocs": {
        "ipv4": [
          "100.4.7.69"
        ]
      },
      "link": "https://www.dan.me.uk/tornodes",
      "id": "TOR-Node-100.4.7.69",
      "title": "As of Wed Oct  2 20:09:48 2013 GMT, 100.4.7.69 has been a TOR exit for 61 days, 2:07:23. Contact: GPG KeyID: 0x1F40CBDC Jeremy <jeremy@acjlaw.net>"
    }
  ]
```
    
