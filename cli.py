#!/usr/bin/env python
from controllers import get_fw_rules,get_users,allow_access,revoke_access,get_rules_by_ip,get_rule_by_cnt
import argparse
import prettytable
import json
from config import *

if __name__=='__main__':
    optparser = argparse.ArgumentParser(description='control firewall via cli.', add_help=True)
    subparsers = optparser.add_subparsers(dest='command')

    parser_add = subparsers.add_parser('add')
    parser_add.add_argument('--dport',required=False)
    parser_add.add_argument('ip',nargs='?')
    parser_add.add_argument('--note',dest='note')
    parser_add.add_argument('--adduser',dest='user',required=False)

    parser_del = subparsers.add_parser('del')
    parser_add.add_argument('--deluser',dest='user',required=False)
    parser_del.add_argument('ip',nargs=1)


    parser_list = subparsers.add_parser('list')
    parser_list.add_argument('--json',dest='json',action='store_const',const=True)

    args = optparser.parse_args()
    if 'user' in args: user = args.user
    else: user = DEFAULT_ADMIN

    if args.command=='add':
        allow_access(user,args.ip,args.note,dport=args.dport)
    elif args.command=='del':
        if '.' in args.ip[0]:
            dip = args.ip[0]
            rules = get_rules_by_ip(dip)

            for r in rules:
                revoke_access(user,r['source'],r['cnt'],DEFAULT_ADMIN,True)
        else:
            r = get_rule_by_cnt(args.ip[0])
            revoke_access(user,r['source'],r['cnt'],DEFAULT_ADMIN,True)
            

    elif args.command=='list':
        rules,all_allowed = get_fw_rules(by_user=False)
        if args.json:
            for r in rules:
                r['age'] = str(r['age'])
            j = json.dumps(rules,indent=True)
            print j
        else:
            tb = prettytable.PrettyTable(['Cnt','User','Packets','Source IP','Destination Port','Age','Note'])
            for r in rules:
                tb.add_row([r['cnt'],
                            r['user'],
                            r['pkts'],
                            r['source'],
                            r['dport'],
                            r['age'],
                            r['note']])
            print tb
