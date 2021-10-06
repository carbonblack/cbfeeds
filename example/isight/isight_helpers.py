
import csv
import time

def remove_non_ascii(s): return "".join([x for x in s if ord(x)<128])

def get_field(row, field_name, do_remove_non_ascii=False):
    val = row.get(field_name) or row.get(field_name.lower())
    if val:
        if do_remove_non_ascii:
            val = remove_non_ascii(val)
        return val.strip()
    return None

def isight_csv_to_iocs_dict(isight_csv_entries):
    """
    Converts CSV data (with header) to dictionary of dict[tuple] = another dict,
    where tuple = (report_id, title, product_type, report_timestamp_in_epoch_secs)

    and dict[tuple] = {'md5':[...], 'ipaddr':[...], 'domain':[...]}
    """
    iocs_by_report_dict = {}
    if not isight_csv_entries:
        print("no entries provided")
        return iocs_by_report_dict

    reports = []

    for isight_csv in isight_csv_entries:

        iwcsv = csv.DictReader(isight_csv.split('\n'), delimiter=',', quotechar='"')

        i = 0

        for row in iwcsv:
            report_id        = get_field(row, "ReportID")
            report_timestamp = int(get_field(row, "Publishdate_Mysql", True) or time.time())
            title            = get_field(row, 'Title')
            product_type     = get_field(row, 'Product_Type')
            ip               = get_field(row, 'IPs', True)
            domain           = get_field(row, 'Domain', True)
            md5              = get_field(row, 'MD5', True)
            attachment_md5   = get_field(row, 'Attachment_MD5', True)

            i = i + 1

            if not report_id:
                print(("Report did not have a report_id: %s" % title))
                continue

            # @todo consider using 'Related_Domains'

            network_identifier = row.get('Network_Identifier') or row.get('network_identifier')
            file_identifier = row.get('File_Identifier') or row.get('file_identifier')

            #tup = (report_id, title, product_type, report_timestamp)
            tup = report_id

            ips = set() 
            md5s = set()
            domains = set()

            if tup in iocs_by_report_dict:
                ips = set(iocs_by_report_dict[tup]['ipaddr'])
                md5s = set(iocs_by_report_dict[tup]['md5'])
                domains = set(iocs_by_report_dict[tup]['domain'])
     
            else:
                iocs_by_report_dict[tup] = {}


            iocs_by_report_dict[tup]["title"] = title
            iocs_by_report_dict[tup]["product_type"] = product_type
            iocs_by_report_dict[tup]["report_timestamp"] = report_timestamp

            if network_identifier and network_identifier.lower() == "attacker":
                if ip and len(ip) > 0:
                    ips.add(ip)

                if domain and len(domain) > 0:
                    domains.add(domain)

            if file_identifier and file_identifier.lower() == "attacker":
                if md5 and len(md5) > 0:
                    md5s.add(md5)

                if attachment_md5 and len(attachment_md5) > 0:
                    md5s.add(attachment_md5)

            iocs_by_report_dict[tup]['ipaddr'] = list(ips)
            iocs_by_report_dict[tup]['domain'] = list(domains)
            iocs_by_report_dict[tup]['md5'] = list(md5s)

        return iocs_by_report_dict
