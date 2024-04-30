from __future__ import print_function
import sys
import getopt
import getpass
import requests
import urllib.parse
import json
import urllib3
urllib3.disable_warnings()
from random import randrange
import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    print("Usage Goes here!")
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
    if res.status_code == 200:
        results = json.loads(res.content.decode('utf-8'))
#        pp.pprint("RES [" + api + " ] : " + str(results))
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
    results = json.loads(res.content.decode('utf-8'))
    if res.status_code == 200:
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

if __name__ == "__main__":
    DEBUG = False
    VERBOSE = False
    token = ""
    user = ""
    password = ""
    headers = {}
    timeout = 360

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:v', ['--help', '--DEBUG', '--token=', '--creds',
                                                              '--verbose'])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
            VERBOSE = True
        if opt in ('-v', '--verbose'):
            VERBOSE = True
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
    try:
        (qumulo, path) = args[0].split(':')
    except:
        usage()
