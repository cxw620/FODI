# -*- coding: UTF-8 -*-
# 华为云 函数工作流 FODI后端
# 基于CloudFlare Workers代码转写.
# 安全性优化
# 闻君心 2022/02/08 Ver 1.0.beta
# TODO: 安全性优化(如鉴权等)

import json
import time
import urllib.parse

import pytz
import requests

# 变量声明
# -----------------------------------------------------
# 程序运行目录
EXEC_PATH = ""
# 允许的网站目录. 必须采用HTTPS. 可留空
ACCEPT_ORIGIN = ""
# 调试可设为True, 生产环境必须强制HTTPS防止伪造Origin
ACCEPT_HTTP = True
# 展示路径. 留空默认为根目录
EXPOSE_PATH = ""
# OneDrive 初始REFRESHTOKEN.
ONEDRIVE_REFRESHTOKEN = ""
# 加密文件夹的密码文件的文件名.
PASSWD_FILENAME = ".password"
# OneDrive相关信息.
clientId = ""
clientSecret = ""
loginHost = "https://login.microsoftonline.com"
apiHost = "https://graph.microsoft.com"
# redirectUri按实际填写.
redirectUri = "http://localhost/onedrive-login"
# ----------------------------------------------------
distOAUTH = {
    "redirectUri": redirectUri,
    "refresh_token": ONEDRIVE_REFRESHTOKEN,
    "clientId": clientId,
    "clientSecret": clientSecret,
    "oauthUrl": loginHost + "/common/oauth2/v2.0/",
    "apiUrl": apiHost + "/v1.0/me/drive/root",
    "scope": apiHost + "/Files.ReadWrite.All offline_access"
}


# OAUTH = json.dumps(distOAUTH)
# 请求处理模块
# 当使用APIG触发器时，函数返回体必须为如下json格式:
# {"statusCode": 200, "isBase64Encoded": false, "headers": {}, "body": ""}
# 参考请求https://__sourceURL/__functionPath?path=%2F&encrypted=&plain=&passwd=undefined
# "queryStringParameters": {"path": "/"}不需要decode了
# 传入的event:

# 云函数入口及结果处理


def handler(event, content):
    # TODO:安全性优化: 华为云鉴权
    # result就是fetch_file_info的返回的json字符串
    p_log("函数开始执行!")
    # 鉴权1 HTTPS
    if not ACCEPT_HTTP:
        if event['headers']['x-forwarded-proto'] != "https":
            p_log("非法请求: 非HTTPS访问")
            p_log("非法IP: " + str(event['headers']['x-real-ip']))
            return False
    # 鉴权2 Origin
    if 'orgin' in event['headers'] and ACCEPT_ORIGIN:
        if event['headers']['origin'] != ACCEPT_ORIGIN:
            p_log("未授权的Origin!", True)
            p_log("非法Origin: " + str(event['headers']['origin']))
            p_log("非法IP: " + str(event['headers']['x-real-ip']))
            return False
    else:
        if ACCEPT_ORIGIN and (not 'orgin' in event['headers']):
            p_log("未授权的Origin! 空Origin!", True)
            p_log("非法IP: " + str(event['headers']['x-real-ip']))
            return False
    # 鉴权3 华为云APP
    # 暂时不写了
    result = handle_request(event)
    return {
        "statusCode": 200,
        "isBase64Encoded": False,
        "body": result,
        "headers": {
            "Content-Type": "application/json"
        }
    }


# 初始化


def handle_request(_request={}):
    if not _request:
        p_log("空传入!", True)
        return False
    # 获取Access Token
    access_token = fetch_access_token()
    if not access_token:
        p_log("请求Access Token失败", True)
        return False
    # 读取请求链, for 华为函数工作流.
    req_path = event['queryStringParameters']['path']
    req_passwd = event['queryStringParameters']['passwd']
    # 这两个参数应该是原来鉴权用的, 弃用.
    # reqEncrypted = event['queryStringParameters']['encrypted']
    # reqPlain = event['queryStringParameters']['plain']
    return fetch_file_info(req_path, req_passwd, access_token)


def fetch_file_info(_file_path, _passwd, _access_token):
    # 说明: 返回json
    # 获取发起请求用的文件夹名
    if _file_path == "/":
        _file_path = ""
    if _file_path and EXPOSE_PATH:
        _file_path = ":" + EXPOSE_PATH + _file_path
    # encode URL
    _file_path = encode_uri(_file_path)
    # 生成请求URI
    req_uri = distOAUTH['apiUrl'] + _file_path + \
              "?expand=children(select=name,size,parentReference,lastModifiedDateTime,@microsoft.graph.downloadUrl)"
    req_headers = {'Authorization': 'Bearer ' + _access_token}
    # 发起请求, 拿到dist.
    # result = get_data(req_uri, {}, req_headers)
    # result = fetch_form_data(req_uri, {}, {}, req_headers)
    result = requests.get(req_uri, headers=req_headers).text
    try:
        result = json.loads(result)
    except:
        p_log("请求文件列表错误", True)
        return ""
    # 处理返回的信息
    # 文件及文件夹信息列表
    list_files_info = []
    temp_encrypted = []
    temp_count = 0
    for i in range(len(result['children'])):
        item = result['children'][i]
        # 初始化词典
        temp_dist = {}
        # 判断这个文件夹是否加密
        if item['name'] == PASSWD_FILENAME:
            temp_encrypted = [True, temp_count]
        # 信息读入字典
        temp_dist['name'] = item['name']
        temp_dist['size'] = item['size']
        temp_dist['time'] = item['lastModifiedDateTime']
        if '@microsoft.graph.downloadUrl' in item:
            temp_dist['url'] = item['@microsoft.graph.downloadUrl']
        # 字典存入列表
        list_files_info.append(temp_dist)
        # 计数+1
        temp_count += 1
    # 如果加密, 用户会输密码, 发起第二次请求, 判断密码是否正确
    if len(temp_encrypted):
        temp_passwd_file_url = list_files_info[temp_encrypted[1]]['url']
        temp_passwd = get_data(temp_passwd_file_url)
        if str(_passwd) == str(temp_passwd):
            temp_encrypted = []
    # # 功能废弃, 用于"引用"
    # if _fileName:
    #     tempFileDlURL = list_files_info[tempFileID]['url']
    # 返回json文本
    # TODO:解决空文件夹进不去的问题.
    # 处理父文件夹名
    if len(result['children']):
        temp_parent_path = result['children'][0]['parentReference']['path']
    else:
        temp_parent_path = result['parentReference']['path']
    temp_parent_path = temp_parent_path.split(":")[1]
    if EXPOSE_PATH:
        temp_parent_path = temp_parent_path.replace(EXPOSE_PATH, "")
    if not temp_parent_path:
        temp_parent_path = "/"
    # 返回值
    if temp_encrypted:
        temp_files_info = {'parent': temp_parent_path, 'files': [], 'encrypted': ''}
    else:
        temp_files_info = {'parent': temp_parent_path, 'files': list_files_info}
    return json.dumps(temp_files_info, ensure_ascii=False)


def fetch_access_token():
    # 统一采用毫秒int(round(time.time() * 1000))
    # access令牌有效期60分钟, 即3600s
    # refresh token有效期80天, 即6912000000ms
    # expires_in 单位ms
    p_log("获取Access Token.")
    current_time_stamp = int(round(time.time() * 1000))
    # 初始的refresh_token
    temp_refresh_token = distOAUTH['refresh_token']
    # 读取文件存着的accesstoken
    # MD没有键值对这个功能麻烦死了
    with open(EXEC_PATH + 'fodi_token.json', 'r') as f:
        temp_json = f.read()
    p_log(temp_json)
    try:
        if temp_json:
            temp_dict = json.loads(temp_json)
            if (current_time_stamp - temp_dict['save_time']) < (temp_dict['expires_in'] * 1000 - 600000):
                # 在有效期内直接返回即可
                p_log("从缓存获取AccessToken成功")
                return temp_dict['access_token']
            if current_time_stamp - temp_dict['save_time'] < 6912000000:
                # 略微多此一举其实, 如果90天没人访问怎么可能. 肯定会有定时任务的啊.
                temp_refresh_token = temp_dict['refresh_token']
            else:
                p_log("RefreshToken失效", True)
                return False
        # 下面更新Access Token
        url = distOAUTH["oauthUrl"] + "token"
        p_log(url)
        data = {
            "client_id": distOAUTH["clientId"],
            "refresh_token": temp_refresh_token,
            "grant_type": "refresh_token",
            "client_secret": distOAUTH["clientSecret"]
        }
        p_log(data)
        # 返回json->dict
        fetch_result = fetch_form_data(url, {}, data)
        print(fetch_result)
        fetch_result['save_time'] = int(round(time.time() * 1000))
        data_to_save = json.dumps(fetch_result)
        print(data_to_save)
        with open(EXEC_PATH + 'fodi_token.json', 'w') as f:
            f.write(data_to_save)
        p_log("刷新并获取AccessToken成功")
        return fetch_result['access_token']
    except Exception:
        p_log("刷新或获取AccessToken失败")
        p_log(str(Exception), True)
        return ""


# 共用POST模块
def fetch_form_data(_url, _params={}, _postdata={}, _headers={"Content-Type": "application/x-www-form-urlencoded"},
                    _cookies={}, _retry=False):
    if not _url:
        return "no URL input"
    result = requests.post(_url, params=_params,
                           data=_postdata, headers=_headers, cookies=_cookies)
    p_log("POST:" + str(result) + result.text)
    if not result:
        if _retry:
            return False
        else:
            # 递归递归, 有递有归
            p_log("POST:失败, 重试", True)
            fetch_form_data(_url, _params, _postdata, _headers, _cookies, True)
    else:
        # 如果是json返回dict, 否则返回一般的text
        try:
            result_dict = json.loads(result.text)
            return result_dict
        except:
            return result.text


# 共用get模块
# get无视url后面是否有params


def get_data(_url, _params={}, _headers={}, _cookies={}, _retry=False):
    if not _url:
        return "no URL input"
    if _params and len(_url.split("?")) > 1:
        p_log("错误的URL输入:重复请求参数Param", True)
        return ""
    result = requests.get(_url, params=_params,
                          headers=_headers, cookies=_cookies)
    # if not result:
    #     return ""
    p_log("GET:" + str(result) + result.text)
    if not result:
        if _retry:
            return ""
        else:
            # 递归递归, 有递有归
            p_log("GET:失败, 重试", True)
            get_data(_url, _params, _headers, _cookies, True)
    else:
        # 如果是json返回dict, 否则返回一般的text
        try:
            result_dict = json.loads(result.text)
            return result_dict
        except:
            return result.text


# URL操作: encode or decode


def encode_uri(_param):
    if not _param:
        # 返回空字符串最保险
        return ""
    # 如果给来的是字典, 或者说键值对, 或者说js的对象, 就调用urlencode
    if type(_param) == "<class 'dict'>":
        return urllib.parse.urlencode(_param)
    else:
        return urllib.parse.quote(_param)


def decode_uri(_param):
    if not _param:
        return ""
    return urllib.parse.unquote(_param)


# 日志
def p_log(_data, _remind=False):
    def time_str(t=""):
        if not t:
            t = int(time.time())
        try:
            t = int(t)
        except:
            # 如果int失败估计这是字符串.
            try:
                t = int(time.mktime(time.strptime(t, "%Y-%m-%dT%H:%M:%SZ")))
            except:
                # 还不是就返回空字符串
                return ""
        dt = pytz.datetime.datetime.fromtimestamp(t, pytz.timezone('PRC'))
        return dt.strftime('%Y-%m-%d %H:%M:%S %Z')

    now_time = str(time_str(int(time.time())))
    if _remind:
        _remind = "[ERROR] "
    else:
        _remind = "[INFO] "
    print(_remind + now_time + "->" + str(_data))


# # 测试区
# event = {
#     "body": "",
#     "requestContext": {
#         "apiId": "",
#         "requestId": "",
#         "stage": "RELEASE"
#     },
#     "queryStringParameters": {
#         "path": "/",
#         "encrypted": "",
#         "plain": "",
#         "passwd": "001"
#     },
#     "httpMethod": "POST",
#     "pathParameters": {},
#     "headers": {
#         "accept-language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
#         "accept-encoding": "gzip, deflate, br",
#         "x-forwarded-port": "443",
#         "x-forwarded-for": "",
#         "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#         "upgrade-insecure-requests": "1",
#         "host": "50eedf92-c9ad-4ac0-827e-d7c11415d4f1.apigw.cn-north-1.huaweicloud.com",
#         "x-forwarded-proto": "https",
#         "pragma": "no-cache",
#         "cache-control": "no-cache",
#         "x-real-ip": "",
#         "user-agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0"
#     },
#     "path": "/",
#     "isBase64Encoded": True
# }

# print(handler(event, ""))
