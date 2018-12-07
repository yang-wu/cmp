# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云(BlueKing) available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
#from common.django_util import render_json
from common.mymako import render_mako_context
from common.log import logger
import json
from .cmpmanager import CloudManager

def home(request):
    """
    首页
    """
    return render_mako_context(request, '/home_application/home.html')


def account(request):
    """
    开发指引
    """
    return render_mako_context(request, '/home_application/account.html')


def instance(request):
    """
    联系我们
    """
    return render_mako_context(request, '/home_application/instance.html')

def addAccount(request):
    """
    http://dev.paasce-poc.o.qcloud.com:8000/access-keys/addAccount
    { 
        "accessKeyId": "AKIDpTue9TrVAakfKpq32ylJBpEONEsHnUNE",
        "accessKeySecret": "oRp45zjFWdaMsACylQ8sSmtkWKuFONHy",
        "cloudProvider":  "tx",
        "describe": "hahahaha",
        "name": "腾讯云-1"
    }
    { 
        "accessKeyId": "AKIAID5IJRM2SE6HGWVQ",
        "accessKeySecret": "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",
        "cloudProvider":  "aws",
        "describe": "wawawawawa",
        "name": "AWS-1"
    }

    """
      
    if request.method == "POST":
        try:
            data = json.loads(request.body)
        except Exception:
            return render_json(code=400, mes='错误的json')

        values = dict([(k, v) for k, v in data.iteritems() \
                       if not k.startswith('_') and v])

        data = CloudManager(request).addAccount(values)
        print '1111111111'
        print data
        #return render_json(data)
        return render_mako_context(request, '/home_application/account.html')
    
def getAccount(request):
    try:
        page = int(request.GET.get('_page', 1))
    except:
        page = 1
    try:
        count = int(request.GET.get('_count', 25))
    except:
        count = 25
    try:
        search_keyword = request.GET.get('_search_keyword', '')
    except:
        search_keyword = ''
    order_by = request.GET.get('_order_by','creationTime')

    datas = CloudManager(request).getAccount(search_keyword, page, count, order_by)
    print datas
    return datas
    #return render_mako_context(request, '/home_application/test.html')

def getSyncInstances(request):
    """
    http://dev.paasce-poc.o.qcloud.com:8000/instances/getSyncInstances
    { 
       "_id": "DBD34728F84911E8A981080027E27E5E"
    }
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
        except Exception:
            return render_json(400, "错误的json")
        id = data.get('_id')
        datas = CloudManager(request).getSyncInstances(id)
        #return render_json(**datas)
        return render_mako_context(request, '/home_application/test.html')
        
    
def get_instances(request):
    logger.info('3333333333333333333333333333333')
    #datas = CloudManager(request).get_instances(search_keyword, page, count, sort_by)
    #return render_mako_context(request, '/home_application/contact.html')
    #return render_json(**datas)
    return render_mako_context(request, '/home_application/test.html')
