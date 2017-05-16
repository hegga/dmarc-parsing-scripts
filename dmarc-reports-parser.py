#!/usr/bin/env python
import datetime
import mailbox
import os
import xml.etree.cElementTree as etree
import zlib

today = datetime.date.today()
MAILBOX_PATH = '/opt/dmarc-reports/Mail/dmarc-reports/'
STORE_DIR = '/opt/dmarc-reports/var/dmarc-reports-splunk/{}'.format(today.strftime('%d-%h-%Y'))

# dict containing fields and xml paths
XML_FIELDS = {
    'report_metadata':  {
        'date_range_begin': 'date_range/begin',
        'date_range_end': 'date_range/end',
        'email': 'email',
        'extra_contact_info': 'extra_contact_info',
        'org_name': 'org_name',
        'report_id': 'report_id',
    },

    'policy_published': {
        'adkim': 'adkim',
        'aspf': 'aspf',
        'domain': 'domain',
        'p': 'p',
        'pct': 'pct',
    },

    'record': {
        'source_ip': 'row/source_ip',
        'count': 'row/count',
        'disposition': 'row/policy_evaluated/disposition',
        'dkim': 'row/policy_evaluated/dkim',
        'spf': 'row/policy_evaluated/spf',
        'reason_type': 'row/policy_evaluated/reason/type',
        'comment': 'row/policy_evaluated/reason/comment',
        'envelope_to': 'identifiers/envelope_to',
        'header_from': 'identifiers/header_from',
        'dkim_domain': 'auth_results/dkim/domain',
        'dkim_result': 'auth_results/dkim/result',
        'dkim_hresult': 'auth_results/dkim/human_result',
        'spf_domain': 'auth_results/spf/domain',
        'spf_result': 'auth_results/spf/result',
    },
}

def parse_xml(xml_data):
    # store parsed results in dict
    data = {}
    data['report_metadata'] = {}
    data['policy_published'] = {}
    data['record'] = []

    # parse xml data
    tree = etree.fromstring(xml_data)

    for tag in XML_FIELDS:
        for report in tree.findall(tag):
            if tag == 'record':
                record = {}
                for field in XML_FIELDS[tag]:
                    try:
                        record[field] = report.findtext(XML_FIELDS[tag][field], 'NULL')
                    except:
                        record[field] = 'NULL'
                data[tag].append(record)
            else:
                for field in XML_FIELDS[tag]:
                    try:
                        data[tag][field] = report.findtext(XML_FIELDS[tag][field], 'NULL')
                    except:
                        data[tag][field] = 'NULL'
    return data

def parse_report(msg):

    # store results in this list
    result = []

    # iterate through all parts of the message
    for part in msg.walk():

        if part.get_content_type() == 'application/gzip':
            xml_data = zlib.decompress(part.get_payload(decode=True), zlib.MAX_WBITS|32)
            return parse_xml(xml_data)

def parse_into_key_value(data):
    # list of key=value pairs to return
    key_value_list = []

    # parse dict into key=value, add to a list and return
    for key, value in data.items():
        # encode to utf-8
        key = key.encode('utf-8')
        if not isinstance(value, int) and not isinstance(value, type(None)):
            value = value.encode('utf-8')

        # parse into key=value
        if (isinstance(value, int) or isinstance(value, type(None)) or
             ((isinstance(value, str) or isinstance(value, unicode)) and value.isdigit())):
            key_value_list.append('{}={}'.format(key, value))
        else:
            key_value_list.append('{}="{}"'.format(key, value))

    return key_value_list

def main():

    # check if directory to store key=value files in exists, create it if not
    if not os.path.exists(STORE_DIR):
        os.makedirs(STORE_DIR)

    # open maildir mailbox
    inbox = mailbox.Maildir(MAILBOX_PATH, factory=None)

    # store which messages to delete in this list
    messages_to_delete = []
    
    # iterate through all of the messages and save dmarc report to the directory
    for key in inbox.iterkeys():
        msg = inbox[key]
        
        # parse report, if successful mark message for deletion
        result = parse_report(msg)

        if result:
            
            # write results to file to be picked up by splunk
            with open('{}/{}'.format(STORE_DIR, key), 'wb') as f:

                # iterate through each record, add the report_metadata and the policy_published fields
                for record in result['record']:
                    # add report_metadata
                    record.update(result['report_metadata'])

                    # add policy_published
                    record.update(result['policy_published'])

                    # parse record into key=value for easy indexing in Splunk, and join into string
                    logstr = ', '.join(parse_into_key_value(record))

                    # write log line to file
                    f.write('{}\n'.format(logstr))

            # mark e-mail for deletion
            messages_to_delete.append(key)

    # delete messages which has been successfully parsed
    inbox.lock()
    try:
        for msg in messages_to_delete:
            inbox.remove(msg)
    finally:
        inbox.flush()
        inbox.close()

if __name__ == '__main__':
    main()
