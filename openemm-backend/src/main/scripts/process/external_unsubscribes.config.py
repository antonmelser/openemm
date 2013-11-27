# General config
# The WSv2 wsdl you have configured
WSDL_URL = 'http://localhost:8080/openemm-ws2/emmservices.wsdl'
# The extension that will be given to files that have been processed
FILE_PROCESSED_EXTENSION = 'processed'

# mailto List-Unsubsubscribe
# The file glob that should match your list-unsubscribe mailto files (i.e.,
# those sent to your by the ISPs. There should be one email per file
LISTUNSUB_MAILTO_GLOB = '/home/openemm/mailto-unsubs/*.msg'
# The regex used to detect the agnUID/mid in each file. The default value
# matches the pattern used in the example in the default [headerManager]
# urimatrix for mailto. You MUST use a python regex compatible expression
# and you MUST return a named group <uidstr>
LISTUNSUB_MAILTO_UIDSTR_REGEX = r"Delivered-To: DUNS-(?P<uidstr>.*)@"
# The unsubscribe comment added to the mailinglist entry for the user
LISTUNSUB_MAILTO_REMARK = 'List-unsubscribe mailto by user'

# FBLs
# The FBL blacklist file. The file must have one email PER LINE - this system
# does NOT currently perform the actual parsing. The files MUST be csv files
# and you should be able to split with FBL_LINE_SEPARATOR, and then reliably
# determine the column with FBL_LINE_EMAIL_COLUMN
FBL_ACCOUNTING_GLOB = '/home/openemm/fbl-receipt-logs/*.csv'
FBL_UIDSTR_REGEX = r"<(?P<uidstr>.*)@.*>"
FBL_LINE_SEPARATOR = ','
FBL_LINE_EMAIL_COLUMN = 1
FBL_LINE_UID_COLUMN = ''  # the column number or the empty string - do NOT put 0!
FBL_COMPANY = ''  # unused in standard OpenEMM, should always be the empty string
FBL_SKIP_FIRST_LINE = True  # Skip the first line of the csv file?
