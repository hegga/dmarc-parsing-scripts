#!/usr/bin/env python
import base64
import datetime
import email
import mailbox
import os

today = datetime.date.today()
MAILBOX_PATH = '/opt/dmarc-reports/Mail/dmarc-forensics/'
STORE_DIR = '/opt/dmarc-reports/var/dmarc_forensics_splunk/{}'.format(today.strftime('%d-%h-%Y'))

# what fields from the dmarc report should be sent to Splunk
REPORT_FIELDS = {
    'report_sender': 'From',
    'report_message_id': 'Message-ID',
}

def parse_report(msg):

    # store results in this list
    result = []

    # iterate through all parts of the message
    for part in msg.walk():

        # check if the part is the feedback report
        if part.get_content_type() == 'message/feedback-report':

            # extract content
            for x in part.walk():
                if x.get_content_type() == 'text/plain':
                    content = base64.decodestring(x.get_payload(decode=True))

                    # parse key values
                    for line in content.split('\r\n'):
                        try:
                            if line:
                                key, value = line.split(':', 1)
                                value = value.rstrip().lstrip()
                                result.append('{}="{}"'.format(key.lower(), value))
                        except:
                            continue

        # check if the part is rfc822 attachment
        if part.get_content_type() == 'message/rfc822':

            # extract original message            
            orig_msg = email.message_from_string(part.get_payload(0).as_string())

            # extract and decode original subject
            subject, encoding = email.header.decode_header(orig_msg.get('Subject'))[0]
            if encoding:
                orig_subject = subject.decode(encoding)
            else:
                orig_subject = subject

            # strip newline chars
            orig_subject = orig_subject.replace('\r\n', '')
            
            # add subject to result
            result.append('original_mail_subject="{}"'.format(orig_subject.encode('utf-8')))

    return result

def main():

    # check if directory to store attachments in exists, create it if not
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

            # extract and attach sender and message-id of the report to the logs
            for field, value in REPORT_FIELDS.items():
                result.append('{}="{}"'.format(field, str(msg.get(value).replace('"', ''))))

            # join logstring
            logstr = ', '.join(result)
            
            # write results to file to be picked up by splunk
            with open('{}/{}'.format(STORE_DIR, key), 'wb') as f:
                f.write(logstr)

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
