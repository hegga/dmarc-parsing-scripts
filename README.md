# dmarc-parsing-scripts
Collection of scripts for parsing DMARC reports.

Both scripts expects to read e-mails from a Maildir, one script will parse the aggregated reports, while the other will
parse the forensics reports. They write their output in a key value format made for importing into Splunk. Have the Splunk
Universial Forwarder to monitor the STORE_DIR where the scripts will write their output files.
