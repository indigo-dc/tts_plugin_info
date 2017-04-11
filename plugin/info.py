#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import urlparse
import json
import base64
import random
import string
import sys
import traceback
import time
import os

VERSION="1.2.0"

def list_params():
    RequestParams = []
    ConfParams = []
    return json.dumps({'result':'ok', 'conf_params': ConfParams, 'request_params': RequestParams, 'version':VERSION})

def request_info(JObject):
    Credential = info_to_credential(JObject)
    return json.dumps({'result':'ok', 'credential': Credential, 'state': 'user_info'})

def info_to_credential(JObject):
    Version = JObject['watts_version']
    UserId = JObject['watts_userid']
    UserInfo = JObject['user_info']
    UserId_data = str(UserId)+ '=' * (4 - len(UserId) % 4)
    DecodedUserId = str(base64.urlsafe_b64decode(UserId_data))
    OidcCredential = [
        {'name':'WaTTS version', 'type':'text', 'value':Version},
        {'name':'WaTTS userid', 'type':'text', 'value':UserId},
        {'name':'WaTTS userid (decoded)', 'type':'text', 'value':DecodedUserId}]

    for Key in UserInfo:
        KeyName = oidc_key_to_name(Key)
        Type = oidc_key_to_type(Key)
        Name = "%s"%KeyName
        Value = str(UserInfo[Key])
        NewObj = [{'name':Name, 'type':Type, 'value':Value  }]
        OidcCredential = OidcCredential + NewObj

    Json = json.dumps(JObject, sort_keys=True, indent=4, separators=(',',': '))
    WholeJsonObject = [{'name':'json object', 'type':'textfile', 'value':Json, 'rows':20, 'cols':50, 'save_as':'info.json'}]
    OidcCredential = OidcCredential + WholeJsonObject
    return OidcCredential

def oidc_key_to_name(Key):
    if Key == "iss":
        return "Issuer"
    if Key == "sub":
        return "Subject"
    if Key == "name":
        return "Name"
    if Key == "groups":
        return "Groups"
    if Key == "email":
        return "E-Mail"
    if Key == "gender":
        return "Gender"
    return Key


def oidc_key_to_type(Key):
    if Key == "groups":
        return "textarea"
    return "text"

def revoke_info():
    return json.dumps({'result': 'ok'})


def get_jobject():
        Data = ""
        if 'WATTS_PARAMETER' in os.environ:
            Data = os.environ['WATTS_PARAMETER']
        elif len(sys.argv) == 2:
            Data = sys.argv[1]
        else:
            return None
        Json = str(Data)+ '=' * (4 - len(Data) % 4)
        JObject = json.loads(str(base64.urlsafe_b64decode(Json)))
        return JObject


def main():
    try:
        UserMsg = "Internal error, please contact the administrator"

        JObject = get_jobject()
        if JObject != None:
            Action = JObject['action']
            if Action == "parameter":
                print list_params()
            elif Action == "request":
                print request_info(JObject)
            elif Action == "revoke":
                print revoke_info()
            else:
                print json.dumps({"result":"error", "user_msg":"unknown_action"})
        else:
            print json.dumps({"result":"error", "user_msg":"no_parameter"})
    except Exception, E:
        TraceBack = traceback.format_exc(),
        LogMsg = "the plugin failed with %s - %s"%(str(E), TraceBack)
        print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})

if __name__ == "__main__":
    main()
