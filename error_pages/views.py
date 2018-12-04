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
from common.mymako import render_mako_context


def error_404(request):
    """
    404提示页
    """
    return render_mako_context(request, '404.html')


def error_500(request):
    """
    500提示页
    """
    return render_mako_context(request, '500.html')


def error_401(request):
    """
    401提示页
    """
    return render_mako_context(request, '401.html')


def error_403(request):
    """
    403提示页
    """
    return render_mako_context(request, '403.html')
