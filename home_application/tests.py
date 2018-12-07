#! coding=utf-8
from django.db.models import Q
import django.utils.timezone as timezone
import json
import time
import datetime
import sys
from .tencentmanager import TencentManager
from .awsmanager import AWSManager
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