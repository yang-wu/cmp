#! coding=utf-8
import django.utils.timezone as timezone
from common.django_util import tx_quote_plus
import hashlib
import hmac
import requests
import json
import time
import datetime
import sys
import random
import math
from common.log import logger
import base64


reload(sys)
sys.setdefaultencoding("utf-8")

class TencentManager(object):

    def __init__(self, account):

        self.TX_API_URL = 'cvm.api.qcloud.com/v2/index.php?'
        self.accessKeySecret = account.accessKeySecret
        self.account = account
        self.args = {
            'Version': "2017-03-12",
            'SecretId': account.accessKeyId,
            'Timestamp': int(time.time()),
        }

    def doaction_tx(self, **kwargs):
        args = self.args.copy()
        args["Nonce"] = random.randint(1000000, 100000000)
        for x in kwargs:
            args[x] = kwargs[x]
        if 'InstanceId' in args:
            args['InstanceIds.0'] = args.pop('InstanceId')

        if 'VpcIds' in args:
            args['VpcIds.0'] = args.pop('VpcIds')

        try:
            r = requests.get(self.get_api_url(args), headers={"Content-Type": "application/json"}, timeout=5)
        except Exception, e:
            #LOG.error("腾讯云请求异常：%s" % str(e))
            return {"code": 400, "mes": str(e)}

        try:
            data = json.loads(r.content)
            return data['Response']
        except Exception, e:
            #LOG.error("腾讯云操作异常：%s" % r.content)
            return {"code": 400, "mes": r.content}

    def get_api_url(self, args):
        argstring = ""
        if 'Url' in args:
            TX_API_URL = args.pop('Url')
        else:
            TX_API_URL = self.TX_API_URL

        for k in sorted(args):
            if argstring:
                argstring += "&%s=%s" % (k.replace("_", '.'), args[k])
            else:
                argstring += "%s=%s" % (k.replace("_", '.'), args[k])
                
        StringToSign = "GET" + TX_API_URL + argstring
        args["Signature"] = hmac.new(self.accessKeySecret.encode('ascii'), StringToSign,
                                     hashlib.sha1).digest().encode('base64').rstrip()

        url = "https://" + TX_API_URL + argstring + "&Signature=%s" % tx_quote_plus(args["Signature"])

        return url

    def _get_sync_data(self, ):
        datas = []
        regions = self._get_regions()
        for region in regions:
            flag = True
            offset = 0
            while flag:
                instances = self.doaction_tx(Action="DescribeInstances", Region=region['Region'],
                                             Offset=offset)
                instance_size = len(instances.get('InstanceSet', []))
                if instance_size > 0:
                    for value in instances['InstanceSet']:
                        value['region'] = region['Region']
                        value['accessKeyId'] = self.account.accessKeyId
                        value['_sg'] = self._get_securitygroup_tx(region['Region'],
                                                                  value.get('SecurityGroupIds', []))

                        if 'CLOUD' in value.get('SystemDisk', {}).get('DiskType', ''):
                            disk_ids = [value.get('SystemDisk', {}).get('DiskId', '')]
                        else:
                            disk_ids = []

                        if value.get('DataDisks', {}):
                            for v in value.get('DataDisks', []):
                                if 'CLOUD' in v.get('DiskType', ''):
                                    disk_ids.append(v.get('DiskId', ''))

                        if disk_ids:
                            value['_disk_data'] = self._get_disk_data_tx(region['Region'], value.get('InstanceId', ''),
                                                                         disk_ids)
                        else:
                            value['_disk_data'] = {}

                        datas.append(self._format_values_tx(value))
                if instance_size < 100:
                    flag = False
                offset += 100
        return datas

    def _get_disk_data_tx(self, Region, InstanceId, disk_ids):
        datas = {}

        disk_datas = []
        Disks = self.doaction_tx(Action="DescribeDisks", Region=Region,
                                 DiskIds=disk_ids, Url='cbs.tencentcloudapi.com/?')
        for item in Disks.get('DiskSet', []):
            disk_datas.append(self._format_disk_values_tx(item))
        datas['_disks'] = disk_datas

        snapshot_datas = []
        Snapshots = self.doaction_tx(Action="DescribeSnapshots", Region=Region,
                                     FiltersDiskIds=disk_ids, Url='cbs.tencentcloudapi.com/?')
        for item in Snapshots.get('SnapshotSet', []):
            snapshot_datas.append(self._format_snapshot_values_tx(item, InstanceId))
        datas['_snapshots'] = snapshot_datas

        return datas

    def _get_vpc_data_tx(self, Region, InstanceId, VpcIds):
        datas = ''
        vpcs = self.doaction_tx(Action="DescribeVpcs", Region=Region,
                                 VpcIds=VpcIds, Url='vpc.tencentcloudapi.com/?')
        for item in vpcs.get('VpcSet', []):
            return item.get('VpcName','') + item.get('VpcId','')

        return datas

    def _get_securitygroup_tx(self, Region, SecurityGroupIds):

        datas = []
        securityGroup = self.doaction_tx(Action="DescribeSecurityGroups", Region=Region,
                                         SecurityGroupIds=SecurityGroupIds, Url='vpc.tencentcloudapi.com/?')
        for item in securityGroup.get('SecurityGroupSet', []):
            datas.extend(self._get_securitygroupPolicies_tx(Region, item))
        return datas

    def _get_securitygroupPolicies_tx(self, Region, SecurityGroup):

        datas = []
        securityGroupPolicies = self.doaction_tx(Action="DescribeSecurityGroupPolicies", Region=Region,
                                                 SecurityGroupId=SecurityGroup['SecurityGroupId'],
                                                 Url='vpc.tencentcloudapi.com/?')
        datas.extend(self._format_sg_values_tx(securityGroupPolicies, SecurityGroup))
        return datas

    def _get_regions(self, ):
        res = self.doaction_tx(Action='DescribeRegions')
        try:
            regions = res['RegionSet']
        except:
            return []
        return regions

    def update_instance_status(self, instance):

        Response = self.doaction_tx(Action="DescribeInstances", Region=instance.region, InstanceId=instance.instanceId)
        try:
            status = Response['InstanceSet'][0]['InstanceState']
        except Exception as e:
            return instance
        instance.status = status
        instance.save(update_fields=['status'])
        return instance

    def juage_instance_status(self, instance):
        Response = self.doaction_tx(Action="DescribeInstancesStatus", Region=instance.region, InstanceId=instance.instanceId)

        if Response.get('TotalCount',0) == 0:
            return False
        return True

    def _format_values_tx(self, values):
        data = {}
        data['accessKeyId'] = values.get('accessKeyId', '')
        data['instanceId'] = values.get('InstanceId', '')
        data['instanceName'] = values.get('InstanceName', '')
        data['cloudProvider'] = 'tx'
        data['status'] = values.get('InstanceState', '')
        data['region'] = values.get('region', '')
        data['zone'] = values['Placement']['Zone']
        data['instanceType'] = values.get('InstanceType', '')
        data['cpu'] = values.get('CPU', '')
        data['memory'] = values.get('Memory', '')
        data['disk_root'] = values.get('SystemDisk', {}).get('DiskSize', 0)
        data['disk_category'] = values.get('SystemDisk', {}).get('DiskType', '')

        if isinstance(values.get('DataDisks', []), list):
            datadisk = reduce(lambda x, y: x + y, [item.get('DiskSize', 0) for item in values.get('DataDisks', [])])
        else:
            datadisk = 0
        data['disk'] = datadisk + data['disk_root']

        data['outboundBandwidth'] = values.get('InternetAccessible', {}).get('InternetMaxBandwidthOut', '')
        data['inboundBandwidth'] = values.get('inboundBandwidth', '')
        data['innerIp'] = ','.join(values.get('PrivateIpAddresses',[])) if values.get('PrivateIpAddresses', []) else ''
        data['outerIp'] = ','.join(values.get('PublicIpAddresses',[])) if values.get('PublicIpAddresses', []) else ''
        ####PREPAID：表示预付费，即包年包月
        ####POSTPAID_BY_HOUR：表示后付费，即按量计费
        ####CDHPAID：CDH付费，即只对CDH计费，不对CDH上的实例计费。
        data['instancePayStrategy'] = values.get('InstanceChargeType', '')
        #####BANDWIDTH_PREPAID：预付费按带宽结算
        #####TRAFFIC_POSTPAID_BY_HOUR：流量按小时后付费
        #####BANDWIDTH_POSTPAID_BY_HOUR：带宽按小时后付费
        #####BANDWIDTH_PACKAGE：带宽包用户
        data['netPayStrategy'] = values.get('InternetAccessible', {}).get('InternetChargeType', '')
        data['osType'] = values.get('osType', '')
        data['osName'] = values.get('OsName', '')
        data['imageName'] = values.get('imageName', '')
        data['imageType'] = values.get('imageType', '')
        data['imageId'] = values.get('ImageId', '')
        data['vpcid'] = values.get('valuesVirtualPrivateCloud', {}).get('VpcId','')
        data['creationTime'] = values.get('CreatedTime')
        data['expiredTime'] = values.get('ExpiredTime')
        data['_sg'] = values.get('_sg', [])

        data['_disks'] = values.get('_disk_data', {}).get('_disks', [])
        data['_snapshots'] = values.get('_disk_data', {}).get('_snapshots', [])

        return data

    def _format_sg_values_tx(self, value, securitygroup):
        '''return sg_values list'''
        datas = []
        permissions = value.get('SecurityGroupPolicySet', {}).get('Ingress', [])
        permissions.extend(value.get('SecurityGroupPolicySet', {}).get('Egress', []))
        for permisson in permissions:
            data = {}
            data['securityGroupId'] = securitygroup.get('SecurityGroupId', '')
            data['securityGroupName'] = securitygroup.get('SecurityGroupName', '')
            # data['innerAccessPolicy'] = value.get('InnerAccessPolicy','')
            data['description'] = securitygroup.get('SecurityGroupDesc', '')
            # data['instanceId'] = instanceId

            data['direction'] = permisson.get('Direction', '')
            data['portRange'] = permisson.get('Port', '')
            # data['nicType'] = permisson.get('NicType', '')
            data['ipProtocol'] = permisson.get('Protocol', '')
            data['priority'] = permisson.get('PolicyIndex', '')
            data['policy'] = permisson.get('Action', '')
            data['policyDescription'] = permisson.get('PolicyDescription', '')
            data['cidrIp'] = permisson.get('CidrBlock', '')
            timeArray = time.strptime(securitygroup.get('CreatedTime'), "%Y-%m-%d %H:%M:%S")
            data['creationTime'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", timeArray)
            data['updateTime'] = timezone.now()
            datas.append(data)
        return datas

    def _format_disk_values_tx(self, value):
        '''return disk_values'''

        data = {}
        data['disk_id'] = value.get('DiskId', '').strip()
        data['type'] = value.get('DiskUsage', '').strip()
        data['disk_charge_type'] = value.get('DiskChargeType', '').strip()
        data['portable'] = str(value.get('Portable', '')).strip()

        data['disk_name'] = value.get('DiskName', '').strip()
        data['size'] = str(value.get('DiskSize', '')).strip()
        data['status'] = value.get('DiskState', '').strip()
        data['category'] = value.get('DiskType', '').strip()

        data['instance_id'] = value.get('InstanceId', '').strip()
        data['creation_time'] = str(value.get('CreateTime', '')).strip()
        data['detached_time'] = str(value.get('DeadlineTime', '')).strip()

        data['encrypted'] = str(value.get('Encrypt', False)).strip()

        data['cloudProvider'] = 'tx'

        return data

    def _format_snapshot_values_tx(self, value, InstanceId):
        '''return snapshot_values'''

        data = {}
        data['snapshot_id'] = value.get('SnapshotId', '').strip()

        data['source_disk_type'] = value.get('DiskUsage', '').strip()
        data['source_disk_id'] = value.get('DiskId', '').strip()
        data['source_disk_size'] = str(value.get('DiskSize', 0)).strip()
        data['status'] = value.get('SnapshotState', '').strip()
        data['snapshot_name'] = value.get('SnapshotName', '').strip()
        data['progress'] = str(value.get('Percent', 0)).strip()
        if value.get('CreateTime', '').strip():
            timeArray = time.strptime(value.get('CreateTime'), "%Y-%m-%d %H:%M:%S")
            data['creation_time'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", timeArray)

        data['encrypted'] = str(value.get('Encrypt', False)).strip()

        data['instanceId'] = InstanceId
        data['diskId'] = value.get('DiskId', '').strip()
        data['cloudProvider'] = 'tx'

        return data