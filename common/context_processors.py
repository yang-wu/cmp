# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云(BlueKing) available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

context_processor for common(setting)

除setting外的其他context_processor内容，均采用组件的方式(string)
"""
from django.conf import settings
import datetime


def mysetting(request):
    return {
        # 基础信息
        'RUN_MODE': settings.RUN_MODE,
        'APP_ID': settings.APP_ID,
        'SITE_URL': settings.SITE_URL,
        # 静态资源
        'STATIC_URL': settings.STATIC_URL,
        'STATIC_VERSION': settings.STATIC_VERSION,
        # 登录跳转链接
        'LOGIN_URL': settings.LOGIN_URL,
        'LOGOUT_URL': settings.LOGOUT_URL,
        'BK_PAAS_HOST': '%s/app/list/' % settings.BK_PAAS_HOST,
        'BK_PLAT_HOST': settings.BK_PAAS_HOST,
        # 当前页面，主要为了login_required做跳转用
        'APP_PATH': request.get_full_path(),
        'NOW': datetime.datetime.now(),
    }
