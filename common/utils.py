# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云(BlueKing) available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

开发框架公用方法
1. 页面输入内容转义（防止xss攻击）
from common.utils import html_escape, url_escape, texteditor_escape
2. 转义html内容
html_content = html_escape(input_content)
3. 转义url内容
url_content = url_escape(input_content)
4. 转义富文本内容
texteditor_content = texteditor_escape(input_content)
"""
from common.pxfilter import XssHtml
from common.log import logger
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.conf import settings
from django.http import HttpResponse
from itertools import chain
import json
import uuid
import string
import random
import urllib
import pytz
import datetime
import re
import ConfigParser
import os
import platform
import requests

def html_escape(html, is_json=False):
    """
    Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true, the quotation mark character (")
    is also translated.
    rewrite the cgi method
    @param html: html代码
    @param is_json: 是否为json串（True/False） ，默认为False
    """
    # &转换
    if not is_json:
        html = html.replace("&", "&amp;")  # Must be done first!
    # <>转换
    html = html.replace("<", "&lt;")
    html = html.replace(">", "&gt;")
    # 单双引号转换
    if not is_json:
        html = html.replace(' ', "&nbsp;")
        html = html.replace('"', "&quot;")
        html = html.replace("'", "&#39;")
    return html


def url_escape(url):
    url = url.replace("<", "")
    url = url.replace(">", "")
    url = url.replace(' ', "")
    url = url.replace('"', "")
    url = url.replace("'", "")
    return url


def texteditor_escape(str_escape):
    """
    富文本处理
    @param str_escape: 要检测的字符串
    """
    try:
        parser = XssHtml()
        parser.feed(str_escape)
        parser.close()
        return parser.get_html()
    except Exception, e:
        logger.error(u"js脚本注入检测发生异常，错误信息：%s" % e)
        return str_escape


def login_not_required(func):
    func.login_not_required = True
    return func

def active_not_required(func):
    func.active_not_required = True
    return func

def render_json(code=200,mes='',data=[],total=''):
    datas = {
        "code": code,
        "message": mes,
        "data": data,
    }

    if total:
        datas["total"] = total
    else:
        datas["total"] = 0

    if settings.DEBUG:
        indent = 2
    else:
        indent = 0
    js = json.dumps(datas, indent)

    return HttpResponse(js,)

def random_id():
    random_id = str(uuid.uuid1())
    random_id = random_id.upper()
    return random_id.replace("-","")

def random_string(num):
    random_string = str(''.join(random.sample(string.ascii_letters + string.digits, num)))
    random_string = random_string.upper()
    return random_string

def id_generator(size=32, chars=string.ascii_lowercase + string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def tx_quote_plus(s, safe=''):
    return urllib.quote(s, safe)

def albb_quote_plus(s, safe='~'):
    return urllib.quote(s, safe)

def ksyun_quote_plus(s, safe=''):
    return urllib.quote(s, safe)

def status_translate(s):
    datas = {
        # 数字翻译
        "1": "运行中",
        "2": "关闭",

        # 基础
        "running": "运行中",
        "active": "运行中",
        "stopping": "关机中",
        "stopped": "关闭",
        "shutoff": "关闭",
        "shutdown": "关闭",

        # 华为云
        "creating": "创建中",
        "createfailed": "创建失败",
        "restarting": "重启中",
        "closing": "关机中",
        "frozen": "已冻结",

        "build": "创建中",
        "reboot": "重启中",
        "resize": "更新规格中",
        "verify_resize": "更新规格校验中",
        "hard_reboot": "强制重启中",
        "revert_resize": "更新规格回退中",

        # 金山云
        "building": "创建中",
        "paused": "暂停",
        "suspended": "挂起",
        "resized": "离线迁移完成待确认/回退",
        "soft-delete": "已延迟删除，设定周期后自动强制删除",
        "deleted": "已删除",
        "deleting": "删除中",
        "error": "错误",

        # 金山云
        "scheduling": "调度中",
        "block_device_mapping": '块存储设备映射中',
        "networking": '创建网络中',
        "spawning": '主机生成中',
        "image_snapshot": '快照创建中',
        "image_backup": '    备份创建中',
        "updating_password": '主机修改密码中',
        "resize_prep": '准备升级配置/准备离线迁移',
        "resize_migrating": '离线迁移中',
        "resize_migrated": '已离线迁移',
        "resize_finish": '离线迁移完成',
        "resize_reverting": '离线迁移回退中',
        "resize_confirming": '离线迁移确认中',
        "migrating": '在线迁移中',
        "rebooting": '重启中',
        "rebooting_hard": '硬重启中',
        "pausing": '暂停中',
        "unpausing": '取消暂停中',
        "suspending": '挂起中',
        "resuming": '挂起恢复中',
        "starting": '开机中',
        "powering-off": '电源关闭中',
        "powering-on": '电源开启中',
        "rescuing": 'possible task states during rescue 故障恢复中',
        "unrescuing": 'possible task states during unrescue 解除故障恢复状态中',
        "rebuilding": '重装系统中',
        "rebuild_block_device_mapping": '重装系统块设备映射中',
        "rebuild_spawning": '重装系统主机生成中',

        # model错误翻译
        "idcroom matching query does not exist.": '该机房不存在！',
        "rack matching query does not exist.": '该机柜不存在！',

        # vmware
        "powered_off": "关机",
        "powered_on": "运行中",
        "poweredoff": "关机",
        "poweredon": "运行中",
    }

    if s:
        s = s.lower()
    else:
        s = ''

    try:
        result = datas[s]
    except Exception:
        result = s

    return result

def pay_strategy_translate(s):
    datas = {
        # 阿里云
        "prepaid": "包年包月",
        "postpaid": "按量付费",

        # 腾讯云
        # "prepaid": "包年包月",
        "postpaid_by_hour": "按量付费",

        # 金山云
        "monthly": "按月付费",
        "yearly": "按年付费",
    }

    if s:
        s = s.lower()
    else:
        s = ''

    try:
        result = datas[s]
    except Exception:
        result = s

    return result

def disk_category_translate(s):
    datas = {
        # 阿里云
        "cloud": "普通云盘",
        "cloud_basic": "普通云盘",
        "cloud_efficiency": "高效云盘",
        "cloud_ssd": "SSD云盘",
        "ephemeral_ssd": "本地SSD盘",
        "ephemeral": "本地磁盘",
        "ephemeral_basic": "本地磁盘",

        # 腾讯云
        "local_basic": "本地硬盘",
        "local_ssd": "本地SSD硬盘",
        # "cloud_basic": "普通云硬盘",
        # "cloud_ssd": "SSD云盘",
        "cloud_premium": "高性能云硬盘",
    }

    s = s.lower()

    try:
        result = datas[s]
    except Exception:
        result = s

    return result

def is_valid_date(strdate):
    '''判断是否是一个有效的日期字符串'''
    try:
        datetime.datetime.strptime(strdate, "%Y-%m-%d").date()
        return True
    except:
        return False

def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False

def is_internal_ip(ip):
    def ip_into_int(ip):
        # 先把 192.168.1.13 变成16进制的 c0.a8.01.0d ，再去了“.”后转成10进制的 3232235789 即可。
        # (((((192 * 256) + 168) * 256) + 1) * 256) + 13
        return reduce(lambda x,y:(x<<8)+y,map(int,ip.split('.')))

    ip = ip_into_int(ip)
    net_a = ip_into_int('10.255.255.255') >> 24
    net_b = ip_into_int('172.31.255.255') >> 20
    net_c = ip_into_int('192.168.255.255') >> 16
    return ip >> 24 == net_a or ip >> 20 == net_b or ip >> 16 == net_c

def judging_asset_number_format(str):
    p = re.compile('^[a-zA-Z0-9_]{4,18}$')
    if p.match(str):
        return True
    else:
        return False

def getEtcConfig(file_path,items_name):
    # 生成config对象
    conf = ConfigParser.ConfigParser()
    # 用config对象读取配置文件
    sysstr = platform.system()
    
    if (sysstr == "Windows"):
        path = os.path.dirname(__file__)
        parent_path = os.path.dirname(path)
        file_path = parent_path + file_path
        conf.read(file_path)
    else:
        conf.read(file_path)
    return dict(conf.items(items_name))

def sendEmail(to_email,html):
    # 获取email的配置信息
    email_conf = getEtcConfig('/etc/msg/email.conf', 'email_main')

    url = email_conf["url"]
    # 您需要登录SendCloud创建API_USER，使用API_USER和API_KEY才可以进行邮件的发送。
    params = {
        "apiUser": email_conf["api_user"],
        "apiKey": email_conf["api_key"],
        "from": email_conf["from"],
        "fromName": email_conf["from_name"],
        "to": to_email,
        "subject": email_conf["subject"],
        "html": html
    }

    r = requests.post(url, files={}, data=params)
    return r.text

class JsonModel(object):

    def json(self):
        data = {}

        attnames = list(set(chain.from_iterable(
            (field.name, field.attname) if hasattr(field, 'attname') else (field.name,)
            for field in self._meta.get_fields()
            # For complete backwards compatibility, you may want to exclude
            # GenericForeignKey from the results.
            if not (field.many_to_one and field.related_model is None)
        )))
        for item in attnames:
            if not isinstance(getattr(self, item), \
                    (basestring, long, int, float, list, tuple, dict)) \
                    and getattr(self, item):
                data[item] = getattr(self, item).astimezone(pytz.timezone(settings.TIME_ZONE)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                data[item] = getattr(self, item)
        return data

    def json_verbose_name(self):
        data = {}
        attnames = list(set(chain.from_iterable(
            (field.name, field.attname) if hasattr(field, 'attname') else (field.name,)
            for field in self._meta.get_fields()
            # For complete backwards compatibility, you may want to exclude
            # GenericForeignKey from the results.
            if not (field.many_to_one and field.related_model is None)
        )))
        for item in attnames:
            if not isinstance(getattr(self, item), \
                    (basestring, long, int, float, list, tuple, dict)) \
                    and getattr(self, item):
                    data[self._meta.get_field(item).verbose_name] = getattr(self, item).astimezone(pytz.timezone(settings.TIME_ZONE)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                data[self._meta.get_field(item).verbose_name] = getattr(self, item)
        return data



    def attr_list(self):
        attnames = list(set(chain.from_iterable(
            (field.name, field.attname) if hasattr(field, 'attname') else (field.name,)
            for field in self._meta.get_fields()
            # For complete backwards compatibility, you may want to exclude
            # GenericForeignKey from the results.
            if not (field.many_to_one and field.related_model is None)
        )))
        return attnames


