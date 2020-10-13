#coding:utf-8
from time import *
import argparse
import re
import requests
from urllib.parse import urlparse, parse_qs

parser = argparse.ArgumentParser()
parser.add_argument('-domain', help='Target domain to scan', default=0)
parser.add_argument('-threads', help='Number of threads to use', default=0)
parser.add_argument('-delay', help='Number of threads to use', default=2)
parser.add_argument('-cookies', help='HTTP Cookies')
parser.add_argument('-userAgent',help='HTTP User-Agent', default='CORSyN')
args = parser.parse_args()


def get_filename(filename):

    try:
        file = open(filename, 'r')
        array  = file.readlines()
        file.close()
    except:
        print('Unable to open this file :{} '.format(filename))
        exit();

    i = 0

    while i<len(array):
        array[i] = array[i].replace('\n', '')
        i+=1

    return array


def req(url, headers, delay):

    if delay != 0:
        sleep(delay)

    try:
        r = requests.get(url, headers=headers, timeout=6)
    except requests.exceptions.RequestException as e:
        print('Error: {}'.format(e))
    except requests.exceptions.HTTPError as e:
        print('HTTP Error {}'.format(e))
    except requests.exceptions.ConnectionError as e:
        print('Connection Error {}'.format(e))
    except requests.exceptions.Timeout as e:
        print('Timeout Error: {}'.format(e))

    else:
        return r.headers

def origin(headers, malicious_domain, current_url):

    if headers['access-control-allow-origin'] == malicious_domain:
        
        print('(!) - Application Trust Arbitrary Origin : {} '.format(current_url))
        print('Access-Control-Allow-Origin: {}'.format(malicious_domain))
        print('Acess-Control-Allow-Credentials: true\n')

def null_origin(headers, current_url):

    if headers['access-control-allow-origin'] == 'null':

        print('(!) - Application Trust null Origin : {} '.format(current_url))
        print('Access-Control-Allow-Origin: null')
        print('Acess-Control-Allow-Credentials: true\n')

def allow_subdomain(headers, subdomain, current_url):

    if headers['access-control-allow-origin'] == subdomain:

        print('(!) - Application Trust Any Subdomain : {} '.format(current_url))
        print('Access-Control-Allow-Origin: {}'.format(subdomain))
        print('Acess-Control-Allow-Credentials: true\n')


target_url = get_filename('target.txt')
malicious_domain = 'attacker.com'
delay = args.delay


for u in target_url:

    hd_request ={
        'Referer': u,
        'Cookie': '',
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Origin':''}




    hd_request['Origin'] = malicious_domain
    hd_response = req(u, hd_request, delay)

    try:
        origin(hd_response, malicious_domain, u)
    except:
        print('[-] {} [Not Vulnerable] ! '.format(u))

    hd_request['Origin'] = 'null'
    hd_response = req(u, hd_request, delay)

    try:
        null_origin(hd_response, u)
    except:
        print('[-] {} [Not Vulnerable] ! '.format(u))

    urlparsed = urlparse(u)
    subdomain = urlparsed.scheme +'://'+malicious_domain+'.'+urlparsed.netloc

    hd_request['Origin'] = subdomain
    hd_response = req(u, hd_request, delay)

    try:
        allow_subdomain(hd_response, subdomain, u)
    except:
        print('[-] {} [Not Vulnerable] ! '.format(u))
