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

# from django.db import models
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import django.utils.timezone as timezone
from django.db import models
from common.django_util import JsonModel

# Create your models here.

class Instance(models.Model, JsonModel):

    class Meta:
        db_table = 'instance'
        ordering = ['-importTime']

    id = models.CharField(max_length=32,  primary_key=True)
    accessKeyId = models.CharField(max_length=255, null=True,blank=True,verbose_name="云账户keyid")
    instanceId = models.CharField(max_length=256, verbose_name="uuid",)
    instanceName = models.CharField(max_length=32, default='',null=True,blank=True,verbose_name="主机名称")
    cloudProvider = models.CharField(max_length=32, default='',null=True,blank=True,verbose_name="云商")
    status = models.CharField(max_length=128, null=True,blank=True, verbose_name="运行状态")
    region = models.CharField(max_length=64,null=True,blank=True, verbose_name="地域")
    zone = models.CharField(max_length=64, null=True,blank=True, verbose_name="可用区")
    instanceType = models.CharField(max_length=32, null=True,default='', verbose_name="主机类型")
    cpu = models.CharField(max_length=16, blank=True, null=True,verbose_name="CPU")
    memory = models.CharField(max_length=16, null=True,blank=True, verbose_name="内存")
    disk = models.CharField(max_length=32, null=True,blank=True, verbose_name="硬盘")
    outboundBandwidth = models.CharField(max_length=32, null=True,blank=True, verbose_name="上行公网带宽")
    inboundBandwidth = models.CharField(max_length=32, null=True,blank=True, verbose_name="下行公网带宽")
    innerIp = models.TextField(default='',null=True,blank=True,verbose_name="内网IP")
    outerIp = models.TextField(default='',null=True, blank=True,verbose_name="外网IP")
    creationTime = models.DateTimeField(blank=True, verbose_name="创建时间")
    expiredTime = models.DateTimeField(blank=True,null=True,verbose_name="到期时间")
    importTime = models.DateTimeField(default=timezone.now, blank=True, null=True, verbose_name="导入时间")
    instanceNetwork = models.CharField(max_length=128, null=True,blank=True, verbose_name="所属网络")
    osType = models.CharField(max_length=128, default='', null=True,blank=True,verbose_name="操作系统类型")
    osName = models.CharField(max_length=128, default='', null=True,blank=True,verbose_name="操作系统名称")


class Tcmpaccount(models.Model, JsonModel):

    class Meta:
        ordering = ['-creationTime']
        db_table = 'tcmpaccount'
        #unique_together = ("accessKeyId",)

    id = models.CharField(max_length=32, verbose_name="id", primary_key=True)
    cloudProvider = models.CharField(max_length=32, default='', verbose_name="云商")
    name = models.CharField(max_length=64,verbose_name="云账号名称")
    describe = models.TextField(blank=True,verbose_name="描述")
    accessKeyId = models.CharField(max_length=255,default='',verbose_name="key id")
    accessKeySecret = models.TextField(default='',verbose_name="key Secret")
    status = models.CharField(max_length=64, default='正常',verbose_name="状态", blank=True)
    syncStatus = models.CharField(max_length=64,  default='未同步', blank=True, verbose_name="同步状态")
    creationTime = models.DateTimeField(default = timezone.now, blank=True, verbose_name="创建时间")
    syncTime = models.DateTimeField(default = timezone.now,blank=True, verbose_name="同步时间")

