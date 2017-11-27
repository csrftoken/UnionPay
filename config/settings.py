#! /usr/bin/env python
# -*- coding: utf-8 -*-


"""
    银联支付相关配置
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class UnionPayConfig(object):

    # 银联版本号(固定)
    version = "5.1.0"

    # 商户ID(配置项)
    mer_id = "xxxxxxxxxxxx"

    # 前台回调地址(支付成功回调成功)(配置项)
    front_url = "http://公网IP/back/"

    # 后台回调地址(配置项)
    back_url = "http://公网IP/notify/"

    # 证书地址(配置项)
    cert_path = os.path.join(BASE_DIR, "keys", "acp_test_sign.pfx")

    # 证书解密密码(根据实际去调配)(配置项)
    cert_password = "xxxxx"

    # 是否开启测试模式(默认False)(配置项)
    debug = True