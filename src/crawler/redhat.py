#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Red Hat Security Data API（threat severity）：
# https://access.redhat.com/hydra/rest/securitydata/cve.json
# severity 取值：Critical / Important / Moderate / Low
# 页面说明：https://access.redhat.com/security/updates/classification
# -----------------------------------------------

import requests
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from color_log.clog import log


class RedHat(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'Red Hat 安全漏洞（严重性）'
        self.name_en = 'Red Hat Security'
        self.home_page = 'https://access.redhat.com/security/updates/classification'
        self.url_list = 'https://access.redhat.com/hydra/rest/securitydata/cve.json'


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
            params={'per_page': limit},
            timeout = self.timeout
        )
        if response.status_code != 200:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
            return []

        cves = []
        for obj in response.json():
            cve = self.to_cve(obj)
            if cve.is_vaild():
                cves.append(cve)
        return cves


    def to_cve(self, obj):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.id = obj.get('CVE') or ''
        cve.time = (obj.get('public_date') or '').replace('T', ' ').replace('Z', '')

        severity = obj.get('severity') or ''
        cve.url = obj.get('resource_url') or ('https://access.redhat.com/security/cve/' + cve.id)

        # bugzilla_description 为漏洞标题；部分条目为空时用 CVE 编号兜底
        desc = (obj.get('bugzilla_description') or '').strip()
        cve.title = '[%s] %s' % (severity, desc) if desc else ('[%s] %s' % (severity, cve.id))

        # 描述：CVSS 评分 + 受影响包
        parts = []
        score = obj.get('cvss3_score') or obj.get('cvss_score')
        if score is not None:
            parts.append('CVSS: %s' % score)
        packages = obj.get('affected_packages') or []
        if packages:
            parts.append('受影响包: %s' % ', '.join(packages[:8]))
        cve.info = '\n'.join(parts)
        return cve
