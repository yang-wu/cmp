#! coding=utf-8
from django.db.models import Q
import django.utils.timezone as timezone
import json
import time
import datetime
import sys
import boto3
from .models import Instance, Tcmpaccount
from common.django_util import random_id


reload(sys)
sys.setdefaultencoding("utf-8")

class CloudManager(object):

    def __init__(self, request=None):
        self.request = request
        self.access_role = ['admin', 'ResellerAdmin', 'member']
        self.edit_role = ['admin', 'ResellerAdmin']
        self.delete_role = ['admin', 'ResellerAdmin']
        self.admin = "admin"
        self.ResellerAdmin = "ResellerAdmin"

    def addAccount(self, values):
        if not values.get('name', '').strip():
            return {"code": 400, "mes": '云账号名称是必须的'}
        if not values.get('accessKeyId', '').strip():
            return {"code": 400, "mes": 'accessKeyId是必须的'}
        if not values.get('accessKeySecret', '').strip():
            return {"code": 400, "mes": 'accessKeySecret是必须的'}

        if Tcmpaccount.objects.filter(accessKeyId=values.get('accessKeyId').strip()):
            return {"code": 400, "mes": 'accessKeyId重复'}

        if Tcmpaccount.objects.filter(name=values.get('name').strip()):
            return {"code": 400, "mes": '云账号名称重复'}
        
        cloud = Tcmpaccount()
        cloud.id = random_id()
        cloud.name = values.get('name').strip()
        cloud.accessKeyId = values.get('accessKeyId').strip()
        cloud.accessKeySecret = values.get('accessKeySecret').strip()
        cloud.cloudProvider = values.get('cloudProvider', '').strip()
        cloud.describe = values.get('describe', '').strip()

        try:
            cloud.save()
            data = cloud.__dict__
            print "000000000000"
        except Exception as e:
            return {"code": 400, "mes": str(e)}

        return {"code": 200, "data": data}

    def getAccount(self, search_keyword, page, count, order_by='creationTime'):
        filters = {}
        data = []
        start = (page - 1) * count
        end = start + count

        try:
            clouds = Tcmpaccount.objects.filter(**filters).order_by(order_by)
        except Exception:
            clouds = Tcmpaccount.objects.filter(**filters)

        if not search_keyword.strip() == '':
            fq_filter = FuzzyQuery(self.request).get_fuzzy_query_Q('tcmpaccount', search_keyword)
            try:
                clouds = clouds.filter(fq_filter)
            except:
                pass

        try:
            if filter_q:
                clouds = clouds.filter(filter_q)
        except:
            pass

        total = len(clouds)
        clouds = clouds[start:end]
        for item in clouds:
            json_data = item.__dict__
            
            if item.cloudProvider == "tx":
                json_data['cloudProvider'] = '腾讯云'
            elif item.cloudProvider == "aws":
                json_data['cloudProvider'] = 'AWS'
            else:
                pass
            data.append(json_data)
        return {"data": data, "total": total}

   
    def getSyncInstances(self, id, ):
        data = []
        cloudaccount = Tcmpaccount.objects.get(id=id)

        if cloudaccount.cloudProvider == "tx":
            cmp = TencentManager(cloudaccount)
            datas = cmp._get_sync_data()
        elif cloudaccount.cloudProvider == "aws":
            cmp = AWSManager(cloudaccount)
            accessKey = cloudaccount.accessKeyId
            secretKey = cloudaccount.accessKeySecret
            datas = cmp.get_instances(accessKey, secretKey)
        
        try:
            
            for item in datas:
                ins = Instance.objects.filter(instanceId=item["instanceId"]).filter(
                        accessKeyId=cloudaccount.accessKeyId).first()
                if ins:
                    self.create_or_update_Instance(values=item, id=ins.id, tcmpaccount_id=cloudaccount.id)
                else:
                    self.create_or_update_Instance(values=item, id=None, tcmpaccount_id=cloudaccount.id)
            

        except Exception as e:
            return {"code": 400, "mes": str(e)}
        total = len(data)
        return {"data": data, "total": total}



    def create_or_update_Instance(self, values, id=None, tcmpaccount_id=None):
        if id:
            ins = Instance.objects.filter(pk=id)
            ins.update(**values)
            ins = ins[0]
        else:
            ins = Instance()
            ins.id =  random_id()
            ins.accessKeyId =  values['accessKeyId']
            ins.instanceId =  values['instanceId']
            ins.instanceName =  values['instanceName']
            ins.cloudProvider =  values['cloudProvider']
            ins.status =  values['status']
            ins.region =  values['region']
            ins.zone =  values['zone']
            ins.instanceType =  values['instanceType']
            ins.cpu =  values['cpu']
            ins.memory =  values['memory']
            ins.disk =  values['disk']
            ins.outboundBandwidth =  values['outboundBandwidth']
            ins.inboundBandwidth =  values['inboundBandwidth']
            ins.innerIp =  values['innerIp']
            ins.outerIp =  values['outerIp']
            ins.creationTime =  values['creationTime']
            ins.expiredTime = values['expiredTime']
            ins.importTime =  '2018-12-05T07:05:29Z'
            ins.instanceNetwork =  ''
            ins.osType =  values['osType']
            ins.osName =  values['osName']
            try:
                ins.save()
            except Exception as e:
                LOG.error("创建或编辑云主机异常：%s" % str(e))
                return ''

        return ins.id

    def get_instances(self, search_keyword, page=1, count=25, sort_by='-importTime'):
        start = (page - 1) * count
        end = page * count
        filters = {}
        datas = []
        role_type = IdentityManager(self.request).get_user_default_most_role_type(self.request.user)
        if role_type == self.admin:
            pass
        elif role_type == self.ResellerAdmin:
            filters['account_id'] = self.request.user.account_id
        else:
            resource_ids = ResourceManager().getResourceIdsByUser(self.request.user,'server')
            filter_q = Q(user_id=self.request.user.user_id) | Q(id__in=resource_ids)

        ins_server = Instance.objects.filter(**filters).order_by(str(sort_by))
        lan_server = Lanserver.objects.filter(**filters).order_by(str(sort_by))

        if not search_keyword.strip() == '':
            fq_filter = FuzzyQuery(self.request).get_fuzzy_query_Q('instance', search_keyword)
            try:
                ins_server = ins_server.filter(fq_filter)
                lan_server = lan_server.filter(fq_filter)
            except:
                pass

        try:
            if filter_q:
                ins_server = ins_server.filter(filter_q)
                lan_server = lan_server.filter(filter_q)
        except:
            pass

        instances = []
        if ins_server:
            instances.extend(ins_server)
        if lan_server:
            instances.extend(lan_server)
        total = len(instances)

        if page != -1:
            instances = instances[start:end]

        for instance in instances:
            eachdata = instance.json()
            eachdata['_buname'] = '-'
            eachdata['_buid'] = ''
            crs = CIRelation.objects.filter(second_ci_id=instance.id, first_ci_type='Business')
            for item in crs:
                bu = Business.objects.get(bu_id=item.first_ci_id)
                eachdata['_buname'] = bu.name
                eachdata['_buid'] = bu.bu_id

            if eachdata["cloudProvider"] == 'tx':
                eachdata["cloudProvider"] = "腾讯云"
            elif eachdata["cloudProvider"] == 'albb':
                eachdata["cloudProvider"] = "阿里云"
            elif eachdata["cloudProvider"] == 'ksyun':
                eachdata["cloudProvider"] = "金山云"
            elif eachdata["cloudProvider"] == 'hwcloud':
                eachdata["cloudProvider"] = "华为云"
            elif eachdata["cloudProvider"] == 'lan':
                eachdata["cloudProvider"] = "局域网"

            try:
                tcmpacc = Tcmpaccount.objects.get(accessKeyId=instance.accessKeyId, account_id=instance.account_id)
                eachdata['cloud_account_name'] = tcmpacc.name
            except Exception:
                eachdata['cloud_account_name'] = ""

            eachdata["status"] = status_translate(eachdata["status"]) if eachdata["status"] else "未知"
            eachdata.pop('accessKeyId')
            eachdata['user_name'], eachdata['account_name'] = UserManager().get_username_and_accountname(
                instance.user_id)
            #####自定义列表展示
            eachdata['config'] = "CPU: {} 内存:{} 硬盘: {}".format(eachdata["cpu"] + '核' if eachdata["cpu"] else "--",
                                                                   eachdata["memory"] + 'GB' if eachdata["memory"] else "--",
                                                                   eachdata["disk"] + 'GB' if eachdata["disk"] else "--")
            eachdata["region"] = "{}/{}".format(eachdata["region"] if eachdata["region"] else "无",eachdata["zone"] if eachdata["zone"] else "无")
            eachdata["Ip"] = "内网:{}</br>外网:{}".format(eachdata["innerIp"] if eachdata["innerIp"] else "无", eachdata["outerIp"] if eachdata["outerIp"] else "无")
            # agent状态
            if not eachdata["agentStatus"]:
                eachdata["agentStatus"] = '0'
            elif eachdata["agentStatus"] == '0':
                eachdata["agentStatus"] = '0'
            elif (timezone.now() - instance.heartbeat).total_seconds() >= 10:
                eachdata["agentStatus"] = '2'

            # 如果过期时间不为空,且不为“已删除”状态，则判断实例是否过期
            if eachdata["expiredTime"] and eachdata["status"] != '已删除':
                try:
                    expiredTimeArray = time.strptime(eachdata["expiredTime"], "%Y-%m-%d %H:%M:%S")
                    expiredTimeStamp = int(time.mktime(expiredTimeArray))
                    CurrentTimeStamp = int(time.time())

                    if expiredTimeStamp < CurrentTimeStamp:
                        eachdata["status"] = '已过期'
                except:
                    pass

            ####自定义属性
            attr = ExtendAttribute(self.request)
            attr_values =attr.get_extend_attr_values('instance',instance.pk)
            for item in attr_values:
                eachdata[item['attr_name']] = item['attr_value']

            datas.append(eachdata)
        return {"data": datas, "total": total}

    def update_tcmpaccount_name(self, id, name, data):

        filters = {}
        role_type = IdentityManager(self.request).get_user_default_most_role_type(self.request.user)
        if role_type == self.admin:
            pass
        elif role_type == self.ResellerAdmin:
            filters['account_id'] = self.request.user.account_id
        else:
            filters['user_id'] = self.request.user.user_id

        try:
            tcmpaccount = Tcmpaccount.objects.filter(**filters).get(id=id)
        except Exception:
            LOG.error("局域网账号不存在！")
            return {"code": 400, "mes": "局域网账号不存在！"}

        ####user  权限
        identity = IdentityManager(self.request)
        role_type = identity.get_user_default_most_role_type(self.request.user)
        if role_type == self.admin:
            pass
        else:
            perm = identity.judge_resource_perm(tcmpaccount.pk, 'tcmp_account', 'tcmpaccount_add_or_update')
            if not perm:
                return {"code": 400, "mes": '没有权限'}

        if Tcmpaccount.objects.filter(name=name,account_id=tcmpaccount.account_id).exclude(id=id):
            return {"code": 400, "mes": "该局域网账号名已经存在！"}

        tcmpaccount.name = name
        try:
            tcmpaccount.save()
        except Exception as e:
            LOG.error("局域网账号名称修改失败！" + str(e))
            return {"code": 400, "mes": "局域网账号名称修改失败！"}

        #######自定义属性update
        ex_attrs = ExtendAttribute(self.request).update_extend_attr_values('tcmpaccount', id, data)
        datas = tcmpaccount.json()
        for item in ex_attrs:
            datas[item['attr_name']] = item['attr_value']

        return {"mes": 'success!',"data":datas}
    
    

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
    

class AWSManager(object):
        
    def __init__(self, request=None):
        self.request = request
        self.access_role = ['admin', 'ResellerAdmin', 'member']
        self.edit_role = ['admin', 'ResellerAdmin']
        self.delete_role = ['admin', 'ResellerAdmin']
        self.admin = "admin"
        self.ResellerAdmin = "ResellerAdmin"

    def get_instances(self, accessKey, secretKey):
        ec2 = boto3.client('ec2', region_name='ap-southeast-1', aws_access_key_id=accessKey, aws_secret_access_key=secretKey)
        regions = ec2.describe_regions()['Regions']
        instances = []
        for region in regions:
            ec2 = boto3.client('ec2', region_name=region['RegionName'], aws_access_key_id=accessKey, aws_secret_access_key=secretKey) 
            data = ec2.describe_instances()['Reservations']
            if data:
                instance_list = data[0]['Instances']
                for instance in instance_list:
                    instance['image_name'] = ec2.describe_images(ImageIds=[instance['ImageId']])['Images'][0]['Description'] 
                    instances.append(instance)
        print instances
        return instances


