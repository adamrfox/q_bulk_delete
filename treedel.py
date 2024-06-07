#!/usr/bin/python3
from __future__ import print_function
import sys
import getopt
import getpass
import requests
import urllib.parse
import json
import time
import urllib3
urllib3.disable_warnings()
import os
import pprint
pp = pprint.PrettyPrinter(indent=4)
import re

def usage():
    print("Usage Goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def api_login(qumulo, user, password, token):
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = input("User: ")
        if not password:
            password = getpass.getpass("Password: ")
        payload = {'username': user, 'password': password}
        payload = json.dumps(payload)
        autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
        dprint(str(autht.ok))
        auth = json.loads(autht.content.decode('utf-8'))
        dprint(str(auth))
        if autht.ok:
            auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    dprint("AUTH_HEADERS: " + str(auth_headers))
    return(auth_headers)

def qumulo_get(addr, api):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[GET]: retrying..")
            good = False
            time.sleep(5)
    if res.status_code == 200:
        dprint("RESULTS: " + str(res.content))
        results = json.loads(res.content.decode('utf-8'))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def qumulo_put(addr, api, body):
    dprint("API_PUT: " + api + " : " + str(body))
    dprint("BODY: " + str(body))
    good = False
    while not good:
        good = True
        try:
            res = requests.put('https://' + addr + '/api' + api, headers=auth, data=body, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Errror: Retrying....")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[PUT]: retrying..")
            good = False
            time.sleep(5)
    results = json.loads(res.content.decode('utf-8'))
    if res.status_code == 200:
        return (results)
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + '\n')
        exit(3)

def qumulo_post(addr, api, body):
    dprint("API_POST: " + api + " : " + str(body))
    good = False
    while not good:
        good = True
        try:
            res = requests.post('https://' + addr + '/api' + api, headers=auth, data=body, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying....")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT [POST]: retrying..")
            good = False
            time.sleep(5)
    results = json.loads(res.content.decode('utf-8'))
    if res.status_code >= 200 and res.status_code <= 299:
        return (results)
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + '\n')
        exit(3)

def qumulo_delete(addr, api):
    dprint("API_DELETE: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.delete('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error...Retrying...")
            time.sleep(5)
            good = False
    if res.status_code == 200:
        return(res)
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + '\n')
        exit(3)

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

if __name__ == "__main__":
    default_token_file = ".qfsd_cred"
    token_file = ""
    token = ""
    user = ""
    password = ""
    CMDS = ('list', 'abort', 'start')
    timeout = 30
    job_output = []
    TEST = False

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:f:T', ['help', 'DEBUG', 'token=', 'creds=', 'token-file-',
                                                              '--TEST'])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-f', '--token_file'):
            token_file = a
        if opt in ('-T', '--TEST'):
            TEST = True

    qumulo = args.pop(0)
    cmd = args.pop(0)
    if cmd not in CMDS:
        sys.stderr.write('Valid commands are : ' + str(CMDS) + "\n")
        exit(1)
    if not user and not token:
        if not token_file:
            token_file = default_token_file
        if os.path.isfile(token_file):
            token = get_token_from_file(token_file)
    auth = api_login(qumulo, user, password, token)
    dprint(str(auth))
    if cmd == 'list':
        filter = ""
        try:
            filter = args[0]
        except:
            pass
        job_list = qumulo_get(qumulo, '/v1/tree-delete/jobs/')
        first = True
        for job in job_list['jobs']:
            if filter and not re.search(filter, job['initial_path']):
                continue
            if first:
                job_output.append(["Path:", "Directories:", "Files:"])
                first = False
            dirs_done = int(job['initial_directories']) - int(job['remaining_directories'])
            files_done = int(job['initial_files']) - int(job['remaining_files'])
            job_output.append([job['initial_path'], str(dirs_done) + '/' + job['initial_directories'], str(files_done) +
                               '/' + job['initial_files']])
        widths = [max(map(len, col)) for col in zip(*job_output)]
        for row in job_output:
            print ("  ".join((val.ljust(width) for val, width in zip(row, widths))))
        exit(0)
    if cmd == "abort":
        if args[0].lower() == 'all':
            job_list= ['.']
        else:
            args_s = ''.join(args)
            job_list = args_s.split(',')
        running_jobs = qumulo_get(qumulo, '/v1/tree-delete/jobs/')
        for j in running_jobs['jobs']:
            for job_candidate in job_list:
#                print('JC: ' + job_candidate)
                if re.search(job_candidate, j['initial_path']):
                    print("Aborting " + j['initial_path'])
                    if not TEST:
                        qumulo_delete(qumulo, '/v1/tree-delete/jobs/' + str(j['id']))
        exit (0)
    if cmd == "start":
        args_s = ''.join(args)
        job_list = args_s.split(',')
        running_jobs = qumulo_get(qumulo, '/v1/tree-delete/jobs/')
        job_index = {}
        for j in running_jobs['jobs']:
            job_index[j['initial_path']] = j['id']
        pp.pprint(job_index.keys())
        for job_candidate in job_list:
            if job_candidate in job_index.keys():
                print("Job already running on " + job_candidate)
                continue
            else:
                print("Deleting " + job_candidate)
                if not TEST:
                    payload = json.dumps({'id': job_index[job_candidate]})
                    qumulo_post(qumulo, '/v1/tree-delete/jobs', payload)
        exit(0)

