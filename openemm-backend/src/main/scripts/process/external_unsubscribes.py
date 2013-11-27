#!/usr/bin/python
# vim: set fileencoding=utf-8 :

import re, os, glob, types, calendar, imp, argparse

parser = argparse.ArgumentParser()
parser.add_argument('--config', help='Config file to process', dest='config')

args = parser.parse_args()

if args.config:
    configfile = args.config
else:
    configfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'external_unsubscribes.config.py')

import agn

config = imp.load_source('config', configfile)

if not config.FBL_COMPANY:
    COMPANY_ID = 1
else:
    COMPANY_ID = config.FBL_COMPANY

from suds.client import Client
from suds.wsse import *

MAILINGLISTS = {}
COMPANYPASSWORDS = {}

from base64 import b64encode

try:
    from haslib import sha1
except:
    from sha import new as sha1

import datetime


class UsernameDigestToken(UsernameToken):
    """
    Represents a basic I{UsernameToken} WS-Security token with password digest
    @ivar username: A username.
    @type username: str
    @ivar password: A password.
    @type password: str
    @ivar nonce: A set of bytes to prevent reply attacks.
    @type nonce: str
    @ivar created: The token created.
    @type created: L{datetime}

    @doc: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0.pdf
    """

    # taken from https://gist.github.com/copitux/5029872
    def __init__(self, username=None, password=None):
        UsernameToken.__init__(self, username, password)
        #self.setcreated()
        fudged_datetime = datetime.datetime.utcnow() - datetime.timedelta(minutes=59)
        self.setcreated(fudged_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"))

        self.setnonce()

    def setnonce(self, text=None):
        """
        Set I{nonce} which is arbitraty set of bytes to prevent
        reply attacks.
        @param text: The nonce text value.
            Generated when I{None}.
        @type text: str

        @override: Nonce save binary string to build digest password
        """
        if text is None:
            s = []
            s.append(self.username)
            s.append(self.password)
            s.append(Token.sysdate())
            m = md5()
            m.update(':'.join(s))
            self.raw_nonce = m.digest()
            self.nonce = b64encode(self.raw_nonce)
        else:
            self.nonce = text

    def xml(self):
        usernametoken = UsernameToken.xml(self)
        password = usernametoken.getChild('Password')
        nonce = usernametoken.getChild('Nonce')
        created = usernametoken.getChild('Created')
        password.set('Type', 'http://docs.oasis-open.org/wss/2004/01/'
                             'oasis-200401-wss-username-token-profile-1.0'
                             '#PasswordDigest')
        s = sha1()
        s.update(self.raw_nonce)
        s.update(created.getText())
        s.update(password.getText())
        password.setText(b64encode(s.digest()))
        nonce.set('EncodingType', 'http://docs.oasis-open.org/wss/2004'
            '/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary')
        return usernametoken


def get_company_ws_auth():
    company_ws_auth = {}
    try:
        db = agn.DBase()
        if not db is None:
            cursor = db.cursor()
            if not cursor is None:
                for r in cursor.queryc('SELECT company_id, username, password FROM webservice_user_tbl'):
                    company_ws_auth[r[0]] = [r[1], r[2]]
                cursor.close()
            else:
                agn.log(agn.LV_ERROR, 'company_ws_auth', 'Unable to get databse cursor')
            db.close()
        else:
            agn.log(agn.LV_ERROR, 'company_ws_auth', 'Unable to create database')
    except agn.error, e:
        agn.log(agn.LV_ERROR, 'company_ws_auth', 'Failed: ' + e.msg)

    if len(company_ws_auth) == 0:
        agn.log(agn.LV_ERROR, 'company_ws_auth', 'There are no WSv2 users defined in the database')
    else:
        agn.log(agn.LV_INFO, 'company_ws_auth', 'Found %s company WS users' % len(company_ws_auth))

    return company_ws_auth


def process_listunsubscribe_fbl(filepath, processed_ext, separator, email_column, uid_column, skip_first_line,
                                uidstr_regex):
    try:
        i = 0
        reg = re.compile(uidstr_regex)
        with open(filepath, "r") as myfile:
            for line in myfile:
                i += 1
                if (skip_first_line and i == 1) or line.strip() == '':  # don't look at headers
                    continue
                uid = None
                email = line.split(separator)[int(email_column) - 1]
                if COMPANY_ID == 'ALL':
                    company_ws_auth_to_blacklist = COMPANY_WS_AUTH.keys()
                elif uid_column:
                    uid = line.split(separator)[int(uid_column) - 1]
                    m = reg.search(uid)
                    if not m is None:
                        uidstr = m.group("uidstr")
                        if not uidstr is None:
                            uid = __scanUID(uidstr)
                            company_ws_auth_to_blacklist = [uid.companyID]
                else:
                    company_ws_auth_to_blacklist = [int(COMPANY_ID)]

                for company in company_ws_auth_to_blacklist:
                    if not email is None and '@' in email:
                        blacklist_in_openemm(email, company)
                    else:
                        agn.log(agn.LV_WARNING, 'blacklisting', 'Unable to parse email from line: ' + str(i)
                                + '. Line contents: ' + line)

            # we don't really need the timestamp here either
            os.rename(filepath, filepath + '.' + str(calendar.timegm(
                datetime.datetime.now().utctimetuple())) + '.' + processed_ext)
    except Exception as ex:
        agn.log(agn.LV_ERROR, 'blacklisting', 'Error processing file ' + filepath + ' to blacklist. Exception: '
                + ex.message)


def process_listunsubscribe_mailto(filepath, processed_ext, uidstr_regex, remark):
    try:
        reg = re.compile(uidstr_regex)

        with open(filepath, "r") as myfile:
            for line in myfile:
                m = reg.search(line)
                if not m is None:
                    uidstr = m.group("uidstr")
                    if not uidstr is None:
                        uid = __scanUID(uidstr)
                        if not uid is None:
                            unsub_from_openemm(uid, remark)
                            break  # only one per email, so can leave already

        # we don't strictly need the timestamp here
        os.rename(filepath, filepath + '.' + str(calendar.timegm(
            datetime.datetime.now().utctimetuple())) + '.' + processed_ext)
    except Exception as ex:
        agn.log(agn.LV_ERROR, 'list-unsubscribe', 'Error processing file ' + filepath
                + ' for list-unsub mailto. Exception: ' + ex.message)


def blacklist_in_openemm(email, company_id):
    wsclient = Client(config.WSDL_URL)
    security = Security()
    token = UsernameDigestToken(COMPANY_WS_AUTH[int(company_id)][0], COMPANY_WS_AUTH[int(company_id)][1])
    security.tokens.append(token)
    wsclient.set_options(wsse=security)
    try:
        wsclient.service.AddBlacklist(email)
    except Exception as ex:
        agn.log(agn.LV_ERROR, 'blacklisting', 'Unable to add ' + email + ' to blacklist via WSv2. Exception: '
                + ex.message)


def unsub_from_openemm(uid, remark):
    wsclient = Client(config.WSDL_URL)
    security = Security()
    token = UsernameDigestToken(COMPANY_WS_AUTH[uid.companyID][0], COMPANY_WS_AUTH[uid.companyID][1])
    security.tokens.append(token)
    wsclient.set_options(wsse=security)
    media_type = 0  # email, would be 4 for SMS
    mailinglist_id = get_mailinglist_from_mailing(uid.mailingID)
    status = 4  # opt-out by user
    user_type = 'W'
    try:
        wsclient.service.SetSubscriberBinding(
            uid.customerID, mailinglist_id, media_type, status, user_type, remark, uid.mailingID)
    except Exception as ex:
        agn.log(agn.LV_ERROR, 'list-unsubscribe', 'Unable to opt-out customer_id: ' + str(uid.customerID)
                + ' for mailing_id:' + str(uid.mailingID) + '. Exception: ' + ex.message)


def get_mailinglist_from_mailing(mailing_id):
    if not mailing_id in MAILINGLISTS:
        db = agn.DBase()
        if not db is None:
            cursor = db.cursor()
            if not cursor is None:
                for r in cursor.queryc('SELECT mailinglist_id FROM mailing_tbl WHERE mailing_id = :mailingID',
                                       {'mailingID': mailing_id}):
                    if not r[0] is None:
                        MAILINGLISTS[mailing_id] = int(r[0])
                cursor.close()
            else:
                agn.log(agn.LV_ERROR, 'mailinglistid', 'Unable to get databse cursor')
                db.close()
        else:
            agn.log(agn.LV_ERROR, 'mailinglistid', 'Unable to create database')
    return MAILINGLISTS[mailing_id]


# Adapted from agn.py - should probably just use that version...
def __scanUID (uidstr):
    uid = agn.UID()
    uid.password = None
    try:
        uid.parseUID(uidstr)
        if uid.companyID in COMPANYPASSWORDS:
            uid.password = COMPANYPASSWORDS[uid.companyID]
        else:
            db = agn.DBase()
            if not db is None:
                cursor = db.cursor()
                if not cursor is None:
                    for r in cursor.queryc('SELECT xor_key FROM company_tbl WHERE company_id = :companyID',
                                           {'companyID': uid.companyID}):
                        if not r[0] is None:
                            if type(r[0]) in types.StringTypes:
                                uid.password = r[0]
                            else:
                                uid.password = str(r[0])
                        else:
                            uid.password = ''
                        COMPANYPASSWORDS[uid.companyID] = uid.password
                    cursor.close()
                else:
                    agn.log(agn.LV_ERROR, 'uid', 'Unable to get databse cursor')
                db.close()
            else:
                agn.log(agn.LV_ERROR, 'uid', 'Unable to create database')
    except agn.error, e:
        agn.log(agn.LV_ERROR, 'uid', 'Failed: ' + e.msg)
    if not uid.password is None and uid.validateUID():
        agn.log(agn.LV_INFO, 'uid', 'UID %s valid' % uidstr)
    else:
        agn.log(agn.LV_WARNING, 'uid', 'UID %s invalid' % uidstr)
        uid = None
    return uid


COMPANY_WS_AUTH = get_company_ws_auth()

for afile in glob.glob(config.LISTUNSUB_MAILTO_GLOB):
    process_listunsubscribe_mailto(afile, config.FILE_PROCESSED_EXTENSION, config.LISTUNSUB_MAILTO_UIDSTR_REGEX,
                                   config.LISTUNSUB_MAILTO_REMARK)

for afile in glob.glob(config.FBL_ACCOUNTING_GLOB):
    process_listunsubscribe_fbl(afile, config.FILE_PROCESSED_EXTENSION, config.FBL_LINE_SEPARATOR,
                                config.FBL_LINE_EMAIL_COLUMN, config.FBL_LINE_UID_COLUMN, config.FBL_SKIP_FIRST_LINE,
                                config.FBL_UIDSTR_REGEX)
