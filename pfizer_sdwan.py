#! /usr/bin/env python
"""
Class with REST API

Example: python pfizer_sdwan.py vmanage_hostname username password

ARGUMENTS:
    vmanage_hostname : Ip address of the vmanage or the dns name of the vmanage
    username : Username to login the vmanage
    password : Password to login the vmanage

Note: All the three arguments are manadatory. This is a sample code.
No error checking/validation/testing/logging - Not production ready.
"""
import json
import requests
import sys
from urllib3.exceptions import InsecureRequestWarning
from utils import json_to_csv, display_sessions, display_summary, url_parse_query

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
## change to /tmp directory
OUTFILE = '/Users/shirkhan/PycharmProjects/Shirin_project1/output/acl_log.csv'
OUTPUTFILE = '/Users/shirkhan/PycharmProjects/Shirin_project1/output/acllog_pagination.csv'
DEVICEID = '4.4.4.4'
ACL_URL = 'https://172.16.104.81:8443/dataservice/statistics/flowlog?query=%7B%22query%22%3A%' \
          '7B%22condition%22%3A%22AND%22%2C%22rules%22%3A%5B%7B%22value%22%3A%5B%2224%22%5D%2C%' \
          '22field%22%3A%22entry_time%22%2C%22type%22%3A%22date%22%2C%22operator%22%3A%22' \
          'last_n_hours%22%7D%5D%7D%7D'


class rest_api_lib:
    def __init__(self, vmanage_ip, username, password):
        self.vmanage_ip = vmanage_ip
        self.session = {}
        self.login(self.vmanage_ip, username, password)

    def login(self, vmanage_ip, username, password):
        """Login to vmanage"""
        base_url_str = 'https://%s/' % vmanage_ip

        login_action = '/j_security_check'

        # Format data for loginForm
        login_data = {'j_username': username, 'j_password': password}

        # Url for posting login data
        login_url = base_url_str + login_action

        sess = requests.session()

        # If the vmanage has a certificate signed by a trusted authority change verify to True
        login_response = sess.post(url=login_url, data=login_data, verify=False)
        byte_content = login_response.content
        content = str(byte_content, 'utf-8')

        if '<html>' in content:
            print("Login Failed")
            sys.exit(0)

        self.session[vmanage_ip] = sess

    def get_request(self, mount_query):
        """GET request flow log - ACL Log"""
        #dictionary to string conversion
        url = "https://%s:8443/dataservice/statistics/flowlog?query=%s" % (self.vmanage_ip, json.dumps(mount_query))
        response = self.session[self.vmanage_ip].get(url, verify=False)
        byte_content = response.content
        data = str(byte_content, 'utf-8')
        #string to dictionary-json
        data_json = json.loads(data)
        return data_json

    def get_bfd_summary_request(self, deviceId):
        """GET request bfd summary"""
        query_param = 'deviceId'
        url = "https://%s:8443/dataservice/device/bfd/summary?%s=%s" % (self.vmanage_ip, query_param, deviceId)
        response = self.session[self.vmanage_ip].get(url, verify=False)
        byte_content = response.content
        data = str(byte_content, 'utf-8')
        data_json = json.loads(data)
        return data_json

    def get_bfd_sessions_request(self, deviceId):
        """GET request bfd session"""
        query_param = 'deviceId'
        url = "https://%s:8443/dataservice/device/bfd/sessions?%s=%s&&&" % (self.vmanage_ip, query_param, deviceId)
        response = self.session[self.vmanage_ip].get(url, verify=False)
        byte_content = response.content
        data = str(byte_content, 'utf-8')
        #string to dictionary-json
        data_json = json.loads(data)
        return data_json

    def get_req_acllog(self, mount_query):
        """GET request flow log - ACL Log"""
        #dictionary to string
        url = "https://%s:8443/dataservice/statistics/flowlog?query=%s" % (self.vmanage_ip, json.dumps(mount_query))
        response_page = self.session[self.vmanage_ip].get(url, verify=False)
        byte_content = response_page.content
        data = str(byte_content, 'utf-8')
        response_all = json.loads(data)
        num_pages = response_all['pageInfo']['count']

        for page in range(2, num_pages + 1):
            res_pgnext = self.session[self.vmanage_ip].get(url, params={'page': page}, verify=False)
            byte_content = res_pgnext.content
            data = str(byte_content, 'utf-8')
            res_pgnext = json.loads(data)
            response_all.update(res_pgnext)

        return response_all


def main(args):
    vmanage_ip, username, password = args[0], args[1], args[2]
    obj = rest_api_lib(vmanage_ip, username, password)

    #query is a dictionary variable
    #query = {"query": {"condition": "AND", "rules": [{"value": ["24"], "field": "entry_time", "type": "date", "operator": "last_n_hours"}]}}
    #pprint(query)

    query = url_parse_query(ACL_URL)
    print('query:', query)
    response = obj.get_request(query)
    print("response:", response)
    """
    Add a validation function if you need to. 
    For Example:
    validate_response(response['data']
    """
    json_to_csv(response['data'], OUTFILE)
    res_acllog = obj.get_req_acllog(query)
    json_to_csv(res_acllog['data'], OUTPUTFILE)
    res_summary = obj.get_bfd_summary_request(DEVICEID)
    res_sessions = obj.get_bfd_sessions_request(DEVICEID)
    display_summary(res_summary['data'])
    display_sessions(res_sessions['data'])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
