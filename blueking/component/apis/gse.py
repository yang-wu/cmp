# -*- coding: utf-8 -*-
from ..base import ComponentAPI


class CollectionsGSE(object):
    """Collections of GSE APIS"""

    def __init__(self, client):
        self.client = client

        self.get_agent_info = ComponentAPI(
            client=self.client, method='POST',
            path='/api/c/compapi{bk_api_ver}/gse/get_agent_info/',
            description=u'Agent心跳信息查询'
        )
        self.get_agent_status = ComponentAPI(
            client=self.client, method='POST',
            path='/api/c/compapi{bk_api_ver}/gse/get_agent_status/',
            description=u'Agent在线状态查询'
        )
