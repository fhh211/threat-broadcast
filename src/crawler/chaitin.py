#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# 长亭漏洞库（CT Stack 雷池/洞鉴）：https://stack.chaitin.com/vuldb/index
# REST API：https://stack.chaitin.com/api/v2/vuln/list/?limit=&offset=
# -----------------------------------------------

import re
import requests
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from color_log.clog import log


class Chaitin(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '长亭漏洞库'
        self.name_en = 'Chaitin VulDB'
        self.home_page = 'https://stack.chaitin.com/vuldb/index'
        self.url_list = 'https://stack.chaitin.com/api/v2/vuln/list/'
        self.url_cve = 'https://stack.chaitin.com/vuldb/detail/'


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def headers(self):
        headers = super().headers()
        headers['Referer'] = self.home_page
        return headers


    def get_cves(self, limit = 10):
        response = requests.get(
            self.url_list,
            headers = self.headers(),
            params={'limit': limit, 'offset': 0},
            timeout = self.timeout
        )
        if response.status_code != 200:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
            return []

        items = (response.json().get('data') or {}).get('list') or []
        cves = []
        for obj in items:
            cve = self.to_cve(obj)
            if cve.is_vaild():
                cves.append(cve)
        return cves


    def to_cve(self, obj):
        cve = CVEInfo()
        cve.src = self.NAME_CH()

        cve.id = obj.get('cve_id') or ''
        cve.url = self.url_cve + str(obj.get('id') or '')
        cve.time = obj.get('disclosure_date') or (obj.get('created_at') or '').split('T')[0]

        severity = (obj.get('severity') or '').upper()
        title = (obj.get('title') or '').strip()
        cve.title = '[%s] %s' % (severity, title) if severity else title

        parts = []
        summary = (obj.get('summary') or '').strip()
        if summary:
            parts.append(summary)
        impact = (obj.get('impact') or '').strip()
        if impact:
            parts.append('影响：' + impact)
        ct_id = obj.get('ct_id') or ''
        if ct_id:
            parts.append('编号：%s' % ct_id)
        cve.info = '\n'.join(parts)
        return cve
