# -*- coding: utf-8 -*-
'''
filedesc: default controller file
'''
from noodles.http import Response
from noodles.templates import render_to_response
from commands import getstatusoutput as gso
from config import PW_FILE,IPT_CHAIN,DEFAULT_ADMIN,IPT_INSPOS
import re

#insert:
#
#format order:
#pkts bytes target     prot opt in     out     source               destination         comment
matchre = re.compile(re.escape('/* ServerAccess user:')+'([^ ]+)'+re.escape(' */')+'$')
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
            user = res.group(1)
            if users and user not in users: raise Exception('unknown user %s'%user)
            if user not in rt: rt[user]=[]
            rt[user].append({'source':source,'cnt':cnt})
            all_allowed.append(source)
    return rt,all_allowed
def get_users():
    u = [rw.split(':')[0] for rw in open(PW_FILE,'r').read().split('\n')]
    return u
def allow_access(user,ip):
    users = get_users()
    rules,all_allowed = get_fw_rules(users)
    if ip not in all_allowed:
        cmd = 'sudo iptables -IINPUT %s -s %s -j ACCEPT -m comment --comment="ServerAccess user:%s"'%(IPT_INSPOS,ip,user)
        st,op=gso(cmd) ; assert st==0
    
def revoke_access(user,ip,cnt):
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
def get_admin(r,d):
    return d
def index(request):
    admin = get_admin(request,DEFAULT_ADMIN)
    if request.method=='POST':
        aip = request.params.get('add-ip')
        if request.params.get('add-ip-btn'):
            allow_access(admin,aip)
        for k in request.params:
            spl = k.split('-')
            if spl[0]=='revoke':
                user = spl[1]
                cnt = spl[2]
                ip = spl[3]
                revoke_access(user,ip,cnt)
    users = get_users()
    rules,all_allowed = get_fw_rules(users)
    for u in users: 
        if u not in rules: rules[u]=[]
    if admin==DEFAULT_ADMIN:
        #show all users' rules
        pass
    else:
        for k in rules:
            if k!=admin: 
                del rules[k]

    c = {'users':users,'rules':rules,'remote_ip':request.remote_addr,'is_admin':admin==DEFAULT_ADMIN,'user':admin}
    return render_to_response('index.html',c)
    #return Response('<h1>Hello, NoodlesFramework!</h1>')
