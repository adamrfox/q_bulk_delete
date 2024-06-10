#!/usr/bin/python3
from __future__ import print_function
import sys
import getopt
import getpass
import requests
import urllib.parse
import json
import os
import time
import urllib3
urllib3.disable_warnings()
from random import randrange
import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    sys.stderr.write("Usage q_bulk_delete.py [-hD] [-c creds] [-t token] [-f token_file] [-j jobs] [-i interval] qumulo path\n")
    sys.stderr.write("-h | --help : Display usage help\n")
    sys.stderr.write("-D | --DEBUG : Generate debug data\n")
    sys.stderr.write("-c | --creds : Specify cluster credentials [user:password]\n")
    sys.stderr.write("-t | --token : Specify access token\n")
    sys.stderr.write("-f | --token-file : Specify access token file\n")
    sys.stderr.write("-j | --jobs: Specify maximium jobs per node [def: 10]\n")
    sys.stderr.write("-i | --interval : Specify wait time between output lines in seconds [def: 30]\n")
    sys.stderr.write("qumulo : Name or IP of a Qumulo node\n")
    sys.stderr.write("path : Starting path for tree deletes\n")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def vprint(message):
    if VERBOSE:
        print(message)
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

def get_node_addr(addr_list):
    return(randrange(len(addr_list)))

def get_del_job_node(jobs, MAX_JOBS):
    sorted_jobs = list(sorted(jobs.items(), key=lambda x:len(x[1])))
    if len(sorted_jobs[0][1]) < MAX_JOBS:
        return(sorted_jobs[0][0])
    else:
        return('')

def tree_delete_jobs(addr):
    ret = qumulo_get(addr, '/v1/tree-delete/jobs/')
    return(len(ret['jobs']))

def tree_delete_jobs_list(addr):
    return(qumulo_get(addr, '/v1/tree-delete/jobs/'))

def update_node_jobs(node, jobs):
    j_id_list = []
    j_list = tree_delete_jobs_list(node)
    for j in j_list['jobs']:
        j_id_list.append(j['id'])
#    pp.pprint(jobs)
    for n in jobs:
        for jid in jobs[n]:
            if jid not in j_id_list:
                dprint("** DELETED " + str(jid) + " from " + str(n))
                jobs[n].remove(jid)
    return(jobs)

def get_name_from_addr(addr, addr_list):
    for x in addr_list:
        if x['address'] == addr:
            return(x['name'])
    return('')

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

if __name__ == "__main__":
    DEBUG = False
    VERBOSE = False
    default_token_file = ".qfsd_cred"
    token_file = ""
    MAX_JOBS_PER_NODE = 10
    token = ""
    user = ""
    password = ""
    headers = {}
    timeout = 360
    addr_list = []
    dir_list = {}
    job_list = {}
    job_queue = []
    node_jobs = {}
    SLEEP_INTERVAL = 30

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:vj:i:f:', ['help', 'DEBUG', 'token=', 'creds',
                                                              'jobs=', 'interval=', 'token-file='])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-j', '--jobs'):
            MAX_JOBS_PER_NODE = int(a)
        if opt in ('-i', '--interval'):
            SLEEP_INTERVAL - int(a)
        if opt in ('-f', '--token-file'):
            token_file = a
    try:
        (qumulo, path) = args[0].split(':')
    except:
        usage()
    if not user and not token:
        if not token_file:
            token_file = default_token_file
        if os.path.isfile(token_file):
            token = get_token_from_file(token_file)
    auth = api_login(qumulo,user,password,token)
    dprint(str(auth))
    net_data = requests.get('https://' + qumulo + '/v2/network/interfaces/1/status/', headers=auth,
                            verify=False, timeout=timeout)
    dprint(str(net_data.content))
    net_info = json.loads(net_data.content.decode('utf-8'))
    node_count = len(net_info)
    for node in net_info:
        if node['interface_details']['cable_status'] == "CONNECTED" and node['interface_details'][
            'interface_status'] == "UP":
            for ints in node['network_statuses']:
                addr_list.append({'name': node['node_name'], 'address': ints['address']})
                node_jobs[ints['address']] = []
    dir_info = qumulo_get(addr_list[get_node_addr(addr_list)]['address'],
                          '/v1/files/' + urllib.parse.quote(path, safe='') + '/info/attributes')
    #    pp.pprint(dir_info)
    if dir_info == "404":
        print('GOT 404 in dir_info')
    dprint(str(dir_info))
    top_id = dir_info['id']
    done = False
    next = ''
    while not done:
        if not next:
            top_dir = qumulo_get(addr_list[get_node_addr(addr_list)]['address'],
                                 '/v1/files/' + top_id + '/entries/?limit=500')
            if top_dir == "404":
                print('GOT 404 in next loop: ' + top_id)
                break
        else:
            top_dir = qumulo_get(addr_list[get_node_addr(addr_list)]['address'], next)
            if top_dir == "404":
                print("GOT 404 in else loop: " + + top_id)
        #        pp.pprint(top_dir)
        for dirent in top_dir['files']:
            if dirent['type'] == "FS_FILE_TYPE_DIRECTORY":
                dir_list[dirent['path']] = {'name': dirent['path'], 'id': dirent['id']}
                job_queue.append(dirent['path'])
        try:
            next = top_dir['paging']['next']
            if not next:
                done = True
        except:
            done = True
#    print(addr_list)
    while len(job_queue) > 0 or tree_delete_jobs(addr_list[get_node_addr(addr_list)]['address']) > 0:
        if len(job_queue) > 0:
            d_node = get_del_job_node(node_jobs, MAX_JOBS_PER_NODE)
            if d_node != '':
                job_dir = job_queue.pop()
                print("Deleting " + dir_list[job_dir]['name'] + " on " + get_name_from_addr(d_node, addr_list))
                payload = json.dumps({'id': dir_list[job_dir]['id']})
                qumulo_post(d_node, '/v1/tree-delete/jobs/', payload)
                node_jobs[d_node].append(dir_list[job_dir]['id'])
                node_jobs = update_node_jobs(addr_list[get_node_addr(addr_list)]['address'], node_jobs)
                continue
            else:
                print("Max number of jobs running.  Queue: " + str(len(job_queue)))
        else:
            j = tree_delete_jobs(addr_list[get_node_addr(addr_list)]['address'])
            print("Waiting for " + str(j) + " jobs to complete")
        node_jobs = update_node_jobs(addr_list[get_node_addr(addr_list)]['address'], node_jobs)
        time.sleep(SLEEP_INTERVAL)
    dprint("FINAL JOB QUEUE: " + str(job_queue))
    dprint("FINAL_TREE_DELETE JOBS: " + str(tree_delete_jobs_list(addr_list[get_node_addr(addr_list)]['address'])))
