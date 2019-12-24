#!/usr/local/bin/python3

import hashlib
import hmac
import uuid
import sys
import base64
import binascii
import argparse
import re
import xml.etree.ElementTree as ET
from lxml import etree
import time
from time import sleep
from binascii import hexlify

from datetime import datetime
import requests

def generate_nonce():
    return uuid.uuid4().hex + uuid.uuid4().hex


def setup_session(client, server):
    url = "http://%s/" % server
    response = client.get(url)
    response.raise_for_status()
    # will have to debug this one as without delay here it was throwing a buffering exception on one of the machines
    sleep(1)


def get_server_token(client, server):
    url = "http://%s/api/webserver/token" % server
    token_response = client.get(url).text
    root = ET.fromstring(token_response)

    return root.findall('./token')[0].text


def get_client_proof(clientnonce, servernonce, password, salt, iterations):
    msg = "%s,%s,%s" % (clientnonce, servernonce, servernonce)
    salted_pass = hashlib.pbkdf2_hmac(
        'sha256', password, bytearray.fromhex(salt), iterations)
    client_key = hmac.new(b'Client Key', msg=salted_pass,
                          digestmod=hashlib.sha256)
    stored_key = hashlib.sha256()
    stored_key.update(client_key.digest())
    signature = hmac.new(msg.encode('utf_8'),
                         msg=stored_key.digest(), digestmod=hashlib.sha256)
    client_key_digest = client_key.digest()
    signature_digest = signature.digest()
    client_proof = bytearray()
    i = 0
    while i < client_key.digest_size:
        client_proof.append(client_key_digest[i] ^ signature_digest[i])
        i = i + 1

    return hexlify(client_proof)


def login2(client, server, user, password):
    #code for last huawei routers
    setup_session(client, server)
    token = get_server_token(client, server)
    url = "http://%s/api/user/challenge_login" % server
    request = ET.Element('request')
    username = ET.SubElement(request, 'username')
    username.text = user
    clientnonce = generate_nonce()
    firstnonce = ET.SubElement(request, 'firstnonce')
    firstnonce.text = clientnonce
    mode = ET.SubElement(request, 'mode')
    mode.text = '1'
    headers = {'Content-type': 'text/html',
               '__RequestVerificationToken': token[32:]}
    response = client.post(url, data=ET.tostring(
        request, encoding='utf8', method='xml'), headers=headers)
    scram_data = ET.fromstring(response.text)
    servernonce = scram_data.findall('./servernonce')[0].text
    salt = scram_data.findall('./salt')[0].text
    iterations = int(scram_data.findall('./iterations')[0].text)
    verification_token = response.headers['__RequestVerificationToken']
    login_request = ET.Element('request')
    clientproof = ET.SubElement(login_request, 'clientproof')
    clientproof.text = get_client_proof(
        clientnonce, servernonce, password, salt, iterations).decode('UTF-8')
    finalnonce = ET.SubElement(login_request, 'finalnonce')
    finalnonce.text = servernonce
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
               '__RequestVerificationToken': verification_token}

    url = "http://%s/api/user/authentication_login" % server
    result = client.post(url, data=ET.tostring(
        login_request, encoding='utf8', method='xml'), headers=headers)
    verification_token = result.headers['__RequestVerificationTokenone']

    return verification_token


def reboot(client, server, user, password):
    verification_token = login2(client, server, user, password)
    url = "http://%s/api/device/control" % server
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
               '__RequestVerificationToken': verification_token}
    client.post(
        url, data='<?xml version:"1.0" encoding="UTF-8"?><request><Control>1</Control></request>', headers=headers)


def login(session):
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    hashedpassword = login_data(token)
    post_data = '<?xml version = "1.0" encoding = "UTF-8"?>\n'
    post_data += '<request><Username>' + USERNAME + '</Username>\n'
    post_data += '<Password>' + hashedpassword + '</Password>\n'
    post_data += '<password_type>4</password_type></request>\n'
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
              }
    api_url = BASEURL + '/api/user/login'
    response = session.post(api_url, data=post_data, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        loggedin = loggedin_check(session)
    else:
        loggedin = False

    return loggedin

def login_data(sessiontoken):
    """ return the authentication credential """
    password = b64_sha256(PASSWORD)
    authstring = USERNAME + password + sessiontoken
    authcred = b64_sha256(authstring)
    return authcred

def logout(session):
    xml = """<?xml version:"1.0" encoding="UTF-8"?><request><Logout>1</Logout></request>"""
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/device/control'
    response = session.post(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
    else:
        message_sent = False
    return message_sent

def b64_sha256(data: str):
    """ This is the one that works, do not remove """
    s256 = hashlib.sha256()
    s256.update(data.encode('utf-8'))
    dgs256 = s256.digest()
    hs256 = binascii.hexlify(dgs256)
    return base64.urlsafe_b64encode(hs256).decode('utf-8', 'ignore')

def get_sessionid_nexttoken(session):
    """ Every system call requires a new token """
    response = session.get(BASEURL + '/api/webserver/SesTokInfo')
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        for results in root.iter('SesInfo'):
            sessionid = results.text
        for results in root.iter('TokInfo'):
            token = results.text
    return(session, sessionid, token)

def contructmessage(phonenumber, message):
    """ Constuct the XML message ready to send"""
    messagedate = datetime.now().isoformat(sep=' ', timespec='seconds')
    smscontent = '<?xml version = "1.0" encoding = "UTF-8"?>'
    smscontent += '<request>'
    smscontent += '<Index>-1</Index>'
    smscontent += '<Phones><Phone>' + phonenumber + '</Phone></Phones>'
    smscontent += '<Sca></Sca>'
    smscontent += '<Content>' + message + '</Content>'
    smscontent += '<Length>' + str(len(message)) + '</Length>'
    smscontent += '<Reserved>1</Reserved>' #SMS_TEXT_MODE_7BIT =1
    smscontent += '<Date>' + messagedate + '</Date>'
    smscontent += '</request>'

    return smscontent

def loggedin_check(session):
    """ validate if we are logged in """
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    api_url = BASEURL + '/api/user/state-login'
    response = session.get(api_url)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        for results in root.iter('State'):
            session_state = results.text
        if session_state == "0":
            # 0 is logged in,  -1 is logged out
            loggedin = True
        else:
            loggedin = False
    else:
        loggedin = False
    return loggedin

build_text_list = etree.XPath("//text()")

def errcode(rep):
    code = 0
    root = ET.fromstring(rep.text)
    error = 0

    for results in root.iter('error'):
        error = results.text

    if error:
        for results in root.iter('code'):
            code = results.text

    return code


def send_sms(session, smstosend):
    """ send a constructed sms message """
    # Need a new token before issuing a config/update
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
              }
    api_url = BASEURL + '/api/sms/send-sms'
    response = session.post(
        api_url, data=smstosend, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
        if errcode(response):
            print("Failed to send SMS - Error : " + errcode(response))
            print(smstosend)
            message_sent = False
    else:
        message_sent = False
    return message_sent



def check_uk_mobile(phonenumber):
    # Check to see if the phone number is correct for the UK
    # ie,  correct length and starts 07 or +447
    # REQUIRED : import re
    rule = re.compile(r'^(07\d{9}|\+?447\d{9})$')
    if rule.search(phonenumber):
        return True
    else:
        return False

def reboot(session):

    xml = """<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"""
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/device/control'
    response = session.post(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True

    else:
        message_sent = False
    return message_sent

#10000000000011010101 = HEX 800D5 = <LTEBand>800D5</LTEBand>
#binary from right to left 1-20
#00000000000000000001 = only 2100 MHZ = Band 1 = <LTEBand>00001</LTEBand>
#00000000000000000100 = only 1800 MHZ = Band 3 = <LTEBand>00004</LTEBand>
#00000000000000010000 = only 850 MHZ = Band 5 = <LTEBand>00010</LTEBand>
#00000000000001000000 = only 2600 MHZ = Band 7 = <LTEBand>00040</LTEBand>
#00000000000010000000 = only 900 MHZ = Band 8 = <LTEBand>00080</LTEBand>
#10000000000000000000 = only 800 MHZ = Band 20 = <LTEBand>80000</LTEBand>


LTE_700 ="8000000"
LTE_800 = "80000" # Band 20
LTE_850 = "10" # Band 5
LTE_900 = "80" # Band 8
LTE_1800 = "4"  # Band 3
LTE_2100 = "1"  # Band 1
LTE_2600 = "40"  # Band 7
LTE_1800_2600 = "44"
LTE_800_1800 ="80004"
LTE_700_1800 ="8000004"
LTE_AUTO = "800C5" # Band 1, 3, 7, 8, 20
LTE_FULL = "800D5" # Band 1, 3, 5, 7, 8, 20
# default LTE BAND 800D5 for E5785
# default LTE BAND 20000800C5 for B618


def getLTE(session):
    # xml = """<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"""

    xml = ""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/net/net-mode'
    response = session.get(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
        print (response.text)
    else:
        message_sent = False
    return message_sent


def getSignal(session):

    xml = ""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/device/signal'
    response = session.get(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
        print (response.text)
    else:
        message_sent = False
    return message_sent

def getSignalLoop(session):

    xml = ""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/device/signal'

    while True:
        response = session.get(api_url, data=xml, headers=headers, cookies=session.cookies)
        time.sleep(1)
        root = ET.fromstring(response.text)
        rsrp = int(root.find('rsrp').text[:-3])
        rsrq = int(root.find('rsrq').text[:-2])
        rssi = int(root.find('rssi').text[:-3])
        sinr = int(root.find('sinr').text[:-2])

        bar=""
        mega=(124+rsrp)
        i=0
        while i < mega:
            bar=bar+"*"
            i=i+1
        if verb:
            print("RSRP " + '%3d' % rsrp +"  SINR " + '%3d' % sinr+"  RSRQ " + '%3d' % rsrq+"  RSSI " + '%3d' % rssi + " --- RSRP :"+bar)
        if not verb:
            print(rsrp)


def getStat(session):

    xml = ""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/monitoring/traffic-statistics'

    t0=time.clock()
    response = session.get(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        print("t0", t0)
        print (response.text)


def getStatLoop(session):
    import xml.etree.ElementTree as ET

    xml = ""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/monitoring/traffic-statistics'


    while True:
        response = session.get(api_url, data=xml, headers=headers, cookies=session.cookies)
        time.sleep(2)
        root = ET.fromstring(response.text)
        rate = root.find('CurrentDownloadRate').text
        bar=""
        mega=int(rate) * 4 / 1000000
        i=0
        while i < mega:
            bar=bar+"*"
            i=i+1
        if verb:
            print("CurrentDownloadRate : " + '%10d' % int(rate) + " Bps "+bar)
        if not verb:
            print(rate)


def changeLTE(session,targetLTE):
    # xml = """<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"""

    xml = """<?xml version="1.0" encoding="UTF-8"?>
        <response>
        <NetworkMode>03</NetworkMode>
        <NetworkBand>3FFFFFFF</NetworkBand>
        <LTEBand>""" + targetLTE + """</LTEBand>
        </response>"""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/net/net-mode'
    response = session.post(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
        if verb:
            print ("LTE Changed to "+targetLTE)
    else:
        message_sent = False
    return message_sent

def main():
    global BASEURL
    global USERNAME
    global PASSWORD
    global verb
    global verification_token
    ROUTER = "192.168.8.1"
    BASEURL = "http://"+ROUTER
    USERNAME = "admin"



    PASSWORD = b"admin"
    phone = "0622334455"
    msg = "HTOOL Message Test"
    verb=False

    # Get Args
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", help="router IP")
    parser.add_argument("-u", help="username")
    parser.add_argument("-p", help="password")
    parser.add_argument("-gb", action='store_true', help="getband in XML format")
    parser.add_argument("-sb", help="setband 700Mhz=8000000 800Mhz=80000 1800Mz=4 2100Mhz=1 2600Mhz=40 (you can add for aggregations)")
    parser.add_argument("-r", action='store_true', help="reboot")
    parser.add_argument("-v", action='store_true', help="verbose mode")
    parser.add_argument("-sms", action='store_true', help="send sms")
    parser.add_argument("-phone", help="phone number")
    parser.add_argument("-msg", help="message to send")
    parser.add_argument("-s", action='store_true', help="signal infos")
    parser.add_argument("-sloop", action='store_true', help="signal infos")
    parser.add_argument("-stat", action='store_true', help="get traffic-statistics")
    parser.add_argument("-statloop", action='store_true', help="get traffic-statistics in loop, download rate in bytes / s")

    args = parser.parse_args()

    if args.v:
        verb=True


    if args.ip:
        if verb:
            print("Custom IP : "+args.ip)
        ROUTER=args.ip
        BASEURL = "http://"+ROUTER
    if args.u:
        if verb:
            print("Custom Username : "+args.u)
        USERNAME = args.u
    if args.p:
        if verb:
            print("Custom Password : " + args.p)
        PASSWORD = args.p.encode('UTF-8')



    session = requests.Session()
    #loggedin = login(session) #old version

    verification_token = login2(session, ROUTER, USERNAME, PASSWORD)

    loggedin=loggedin_check(session)

    if loggedin:
        if verb:
            print("Logged on "+BASEURL)


        if args.gb:
            getLTE(session)

        if args.sb:
            changeLTE(session,args.sb)

        if args.s:
            getSignal(session)

        if args.sloop:
            getSignalLoop(session)

        if args.stat:
            getStat(session)
        if args.statloop:
            getStatLoop(session)

        if args.r:
            reboot(session)

        if args.sms:
            if args.phone:
                phone = args.phone
            if args.msg:
                msg = args.msg[:139]
            messagedate = datetime.now().isoformat(sep=' ', timespec='minutes')
            msg = str(messagedate) + " "+msg
            smstosend = contructmessage(phone, msg)
            if send_sms(session, smstosend):
                if verb:
                    print("Message Sent to " + phone)



        if logout(session):
            if verb:
                print("Logout")
        else :
            if verb:
                print("Logout failed")
    else:
        if verb:
            print("Login Failure")



main()

