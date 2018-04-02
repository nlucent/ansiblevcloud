#!/usr/bin/python

DOCUMENTATION = '''
---
module: vcloud_status
short_description: Check operational status of vCloud VM by name
'''

EXAMPLES = '''
- name: Check status of HostnameN
  vcloud_status:
    vcloud_url: 'https://vcloud-url-goes-here.somecompany.com'
    username: 'vcloud_admin'
    passwd: 'vcloud_passwd'
    hostname: 'HostnameN'
    match_status: "POWERED_ON"
    block: 'yes'
    
'''

from ansible.module_utils.basic import *
import xml.etree.ElementTree as ET
import requests
import time

query_string = "/api/query?type=vm&pageSize=999&name="

def check_vm_noblock(data):
    vc_url = data["vcloud_url"]
    vc_usr = data["username"]
    vc_pwd = data["passwd"]
    hostname = data["hostname"]
    match_status = data['match_status']

    headers = {
        "Accept": "application/*+xml;version=1.5",
        "User-Agent": "Mozilla/5.0"
    }

    if vc_url.endswith('/'):
        vc_url = vc_url[:-1]

    r = requests.post(vc_url + "/api/sessions", auth=(vc_usr, vc_pwd), headers=headers)

    if r.status_code == 200:
        token = r.headers['x-vcloud-authorization']
        headers['x-vcloud-authorization'] = token

        r = requests.get(vc_url + query_string + hostname, auth=(vc_usr, vc_pwd), headers=headers)

        if r.status_code == 200:
            content = r.content
            lines = content.splitlines()
            myline = ''
            for line in lines:
                if hostname in line:
                    myline = line
                    try:
                        tree = ET.fromstring(myline)
                        status = tree.attrib['status']
                        if match_status:
                            if status == match_status:
                                return False, False, { "status": "Success"}
                            else:
                                return False, False, { "status": status}
                        return False, False, {"status": status}

                    except ET.ParseError as e:
                        return True, False, {"status": "XML ParseError"}
            return True, False, {"status": "Name not found"}

    return True, False, { "status": "Error authenticating"}


def check_vm_block(data): 
    vc_url = data["vcloud_url"]
    vc_usr = data["username"]
    vc_pwd = data["passwd"]
    hostname = data["hostname"]
    match_status = data['match_status']

    headers = {
        "Accept": "application/*+xml;version=1.5",
        "User-Agent": "Mozilla/5.0"
    }

    if vc_url.endswith('/'):
        vc_url = vc_url[:-1]

    r = requests.post(vc_url + "/api/sessions", auth=(vc_usr, vc_pwd), headers=headers)

    if r.status_code == 200:
        token = r.headers['x-vcloud-authorization']
        headers['x-vcloud-authorization'] = token
        mystatus = ''

        while mystatus != match_status:
            r = requests.get(vc_url + query_string + hostname, auth=(vc_usr, vc_pwd), headers=headers)

            if r.status_code == 200:
                content = r.content
                lines = content.splitlines()
                myline = ''
                for line in lines:
                    if hostname in line:
                        myline = line
                        try:
                            tree = ET.fromstring(myline)
                            mystatus = tree.attrib['status']
                            if mystatus == match_status:
                                return False, False, { "status": "Success"}
                            time.sleep(1)

                        except ET.ParseError as e:
                            return True, False, {"status": "XML ParseError"}
        return True, False, {"status": "Name not found"}

    return True, False, { "status": "Error authenticating"}

def main():

    fields = {
        "vcloud_url": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "passwd": {"required": True, "type": "str"},
        "hostname": {"required": True, "type": "str"},
        "match_status": {"required": False, "type": "str"},
        "block": {
            "default": "no",
            "choices": ['yes', 'no'],
            "type": 'str'
        },
    }

    choice_map = {
        "yes": check_vm_block,
        "no": check_vm_noblock,
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(module.params['block'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error checking vm state", meta=result)

if __name__ == '__main__':
    main()
