from virus_total_apis import PublicApi
import requests
import json

API_KEY = "KEY TO API"
api = PublicApi(API_KEY)


def domain_report(domain):

    response = api.get_domain_report(domain)
    return response


def ip_report(ip):

    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    url_with_ip = url + ip

    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url_with_ip, headers=headers)
    response_in_json = response.json()
    return response_in_json


def url_report(url):

    response = api.get_url_report(url)
    return response