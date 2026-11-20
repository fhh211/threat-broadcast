#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# CISA KEV（已知被利用漏洞目录）：https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# 官方 JSON Feed：https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# -----------------------------------------------

import re
import requests
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from color_log.clog import log


class CisaKev(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'CISA 已知被利用漏洞（KEV）'
        self.name_en = 'CISA KEV'
        self.home_page = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
        self.url_list = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self, limit = 10):
        response = requests.get(
            self.url_list,
            headers = self.headers(),
            timeout = self.timeout
        )
        if response.status_code != 200:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
            return []

        # KEV 列表默认按 dateAdded 升序，取末尾最新条目
        items = response.json().get('vulnerabilities') or []
        items = sorted(items, key=lambda x: (x.get('dateAdded') or '', x.get('cveID') or ''), reverse=True)
        cves = []
        for obj in items[:limit]:
            cve = self.to_cve(obj)
            if cve.is_vaild():
                cves.append(cve)
        return cves


    def to_cve(self, obj):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.id = obj.get('cveID') or ''
        cve.time = obj.get('dateAdded') or ''
        cve.url = '%s#%s' % (self.home_page, cve.id)

        # 标题：厂商 + 产品 + 漏洞名，去掉冗余空白
        vendor = obj.get('vendorProject') or ''
        product = obj.get('product') or ''
        name = obj.get('vulnerabilityName') or ''
        cve.title = ' '.join(('%s %s %s' % (vendor, product, name)).split())

        # 描述：短描述 + 处置建议
        parts = [obj.get('shortDescription') or '']
        action = obj.get('requiredAction') or ''
        if action:
            parts.append('处置建议：' + action)
        cve.info = '\n'.join(p.strip() for p in parts if p.strip())
        return cve
