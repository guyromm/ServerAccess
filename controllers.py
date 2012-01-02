# -*- coding: utf-8 -*-
'''
filedesc: default controller file
'''
from noodles.http import Response
from noodles.templates import render_to_response
from commands import getstatusoutput as gso
from config import PW_FILE,IPT_CHAIN,DEFAULT_ADMIN,IPT_INSPOS,DIGEST_ZONE
import re,json,time,base64,datetime

#insert:
#
#format order:
#pkts bytes target     prot opt in     out     source               destination         comment
matchre = re.compile(re.escape('/* ')
                     +'(|--comment=)'
                     +re.escape('ServerAccess d:')
                     +'(?P<data>[^ ]+)'
                     +re.escape(' */')+'$')
strrestr = ''
for fn in ['pkts','bytes','target','prot','opt','in','out','source','destination','comment']:
    if len(strrestr): strrestr+='([ ]{1,})'
    strrestr+='(?P<%s>[^ ]+)'%fn
strre = re.compile('^%s'%strrestr)

def get_fw_rules(users=None):
    st,op = gso('sudo iptables -tfilter -nvL %s'%IPT_CHAIN)
    assert st==0
    rt = {} ; all_allowed=[]
    cnt=0
    for row in op.split('\n'):
        row = row.strip()
        res = matchre.search(row)
        rule_params = strre.search(row)
        if not rule_params: continue
        cnt+=1
        #print 'cnt %s : %s'%(cnt,rule_params.groups())
        if res:
            #print 'searching %s\nwith\n%s'%(strrestr,row)

            source = rule_params.group('source')
            dtraw = res.group('data')
            dt = json.loads(base64.b64decode(dtraw))
            user = dt['u']
            stamp = dt['s']
            if users and user not in users: raise Exception('unknown user %s'%user)
            if user not in rt: 
                #raise Exception('adding user %s because not in %s'%(user,rt.keys()))
                rt[user]=[]
            rt[user].append({'source':source,'cnt':cnt,'pkts':rule_params.group('pkts'),'age':(datetime.datetime.now()-datetime.datetime.fromtimestamp(stamp))})
            all_allowed.append(source)
    return rt,all_allowed
def get_users():
    fconts = open(PW_FILE,'r').read()
    rt=[]
    for rw in fconts.split('\n'):
        spl = rw.split(':')
        if len(spl)<2: continue
        #print 'going over %s'%spl
        if spl[1]==DIGEST_ZONE:
            rt.append(spl[0])
    return rt
def allow_access(user,ip):
    users = get_users()
    rules,all_allowed = get_fw_rules(users)
    if ip not in all_allowed:
        dt = base64.b64encode(json.dumps({'u':user,'s':time.time()}))
        cmd = 'sudo iptables -IINPUT %s -s %s -j ACCEPT -m comment --comment="ServerAccess d:%s"'%(IPT_INSPOS,ip,dt)
        print cmd
        st,op=gso(cmd) ; assert st==0
    
def revoke_access(user,ip,cnt,op_user,is_admin):
    #we allow admin to op on all |  or user to operate on himself
    if not (is_admin or user==op_user): raise Exception('auth violation')
    users = get_users()
    r,aips = get_fw_rules(users)
    assert '.' in ip
    ur = r[user]
    for r in ur:
        print 'comparing %s with ip %s , cnt %s'%(r,ip,cnt)
        if r['source']==ip and str(r['cnt'])==str(cnt):
            cmd = 'sudo iptables -DINPUT %s'%r['cnt']
            st,op = gso(cmd) ; assert st==0

    pass
class AuthErr(Exception):
    pass
def get_admin(r,d):
    if not r.headers.get('Authorization'):
        raise AuthErr('no authorization found')

    username = re.compile('username="([^"]+)"').search(r.headers.get('Authorization'))
    if username:
        return username.group(1)
    return d
ipre = re.compile('^'+"\.".join(["(\d+)" for i in range(1,5)])+'$')

def index(request):
    try:
        admin = get_admin(request,DEFAULT_ADMIN)
    except AuthErr, e:
        r = Response()
        r.status=403
        r.body = 'looks like you are not authorized: %s'%e
        return r
    is_admin = (admin==DEFAULT_ADMIN)
    if request.method=='POST':
        aip = request.params.get('add-ip')
        #raise Exception(ipre)
        assert ipre.search(aip)
        if request.params.get('add-ip-btn'):
            allow_access(admin,aip)
        for k in request.params:
            spl = k.split('-')
            if spl[0]=='revoke':
                user = spl[1]
                cnt = int(spl[2])
                ip = spl[3] ; assert ipre.search(ip)
                revoke_access(user,ip,cnt,admin,is_admin)
    users = get_users()
    rules,all_allowed = get_fw_rules(users)
    for u in users: 
        if u not in rules: rules[u]=[]
    if admin==DEFAULT_ADMIN:
        #show all users' rules
        pass
    else:
        for k in rules.keys():
            if k!=admin: 
                del rules[k]
        users = [admin]
    remote_addr = request.headers.get('X-Forwarded-For')
    if not remote_addr: raise AuthErr('no remote addr in X-Forwarded-For header')
    c = {'users':users,'rules':rules,'remote_ip':remote_addr,'is_admin':is_admin,'user':admin}
    return render_to_response('index.html',c)
    #return Response('<h1>Hello, NoodlesFramework!</h1>')
