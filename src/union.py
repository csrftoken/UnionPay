#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
    银联支付相关实现(支付, 验证签名等, )
"""

from config.settings import UnionPayConfig

from urllib import parse

import base64
import OpenSSL
import hashlib
import datetime
import requests

"""
银联支付接口类
    1, 前台回调地址和后台回调地址均为post请求, 后台回调用于处理订单相关处理, 前台回调用户点击会返回商户界面
    2, 此用例为沙箱测试环境, 如果使用正式环境, 修改 UnionPayConfig 此相关参数即可
    3, 支付可用(测试环境可使用该卡号进行支付):
    
        姓名: 互联网
        卡号: 6221558812340000
        手机号码: 13552535506
        密码: 123456
        有效期: 2311
        CVN2: 123
        证件号: 341126197709218366
        手机验证码: 123456
        
"""


class UnionTradeType(object):
    pay = "01"
    query = "00"
    revoke = "31"
    refund = "04"
    auth = "02"
    auth_revoke = "32"
    auth_complete = "03"
    auth_complete_revoke = "33"
    file_transfer = "76"
    # 00：查询交易
    # 01：消费
    # 02：预授权
    # 03：预授权完成
    # 04：退货
    # 05：圈存
    # 11：代收
    # 12：代付
    # 13：账单支付
    # 14：转账（保留）
    # 21：批量交易
    # 22：批量查询
    # 31：消费撤销
    # 32：预授权撤销
    # 33：预授权完成撤销
    # 71：余额查询
    # 72：实名认证-建立绑定关系
    # 73：账单查询
    # 74：解除绑定关系
    # 75：查询绑定关系
    # 77：发送短信验证码交易
    # 78：开通查询交易
    # 79：开通交易
    # 94：IC卡脚本通知


class UnionPay(object):
    """
    银联支付接口类
    """

    def __init__(
            self,
            version,
            mer_id,
            front_url,
            back_url,
            backend_url,
            cert_path,
            debug=False
    ):
        self.version = version
        self.mer_id = mer_id
        self.front_url = front_url
        self.back_url = back_url
        self.backend_url = backend_url
        self.cert = {}
        self.cert_id = self.__get_cert_id(cert_path)

        if debug is True:
            # 支付网关
            self.gateway = "https://gateway.test.95516.com/gateway/api/frontTransReq.do"
            # 查询网关
            self.query_gateway = "https://gateway.test.95516.com/gateway/api/queryTrans.do"
        else:
            self.gateway = "https://gateway.95516.com/gateway/api/frontTransReq.do"
            self.query_gateway = "https://gateway.95516.com/gateway/api/queryTrans.do"

    def build_request_data(self, order_id, txn_amt, **kwargs):
        """
        构建请求数据
        :param order_id: 商户订单号
        :param txn_amt: 交易金额(单位: 分)
        :return:
        """
        request_data = {
            "version": self.version,  # 版本
            "encoding": "utf-8",  # 编码
            "txnType": UnionTradeType.pay,  # 交易类型  01：消费
            "txnSubType": "01",  # 交易子类  01：自助消费
            "bizType": "000201",  # 产品类型  000201：B2C网关支付
            "frontUrl": self.front_url,  # 前台通知地址
            "backUrl": self.back_url,  # 后台通知地址 需外网
            "signMethod": "01",  # 签名方法  01：RSA签名
            "channelType": "07",  # 渠道类型  07：互联网
            "accessType": "0",  # 接入类型  0：普通商户直连接入
            "currencyCode": "156",  # 交易币种  156：人民币
            "merId": self.mer_id,  # 商户代码
            "txnAmt": txn_amt,  # 订单金额(单位: 分)
            "txnTime": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),  # 订单发送时间
            "certId": self.cert_id,
            "orderId": order_id,
            "signature": ""
        }
        request_data.update(**kwargs)
        self.get_sign(request_data)
        return request_data

    def get_sign(self, data):
        """
        获取签名
        :param data:
        :return:
        """
        sha256 = hashlib.sha256(self.build_sign_str(data).encode("utf-8")).hexdigest()
        private = OpenSSL.crypto.sign(self.cert["pkey"], sha256, "sha256")
        data["signature"] = str(base64.b64encode(private), encoding="utf-8")

    def pay_html(self, request_data):
        result = """<html>
             <head>
                 <meta http-equiv="Content-Type" content="text/html;charset="utf-8"/>
             </head>
             <body onload="javascript:document.pay_form.submit();">
                 <form id="pay_form" name="pay_form" action="{}" method="post">""".format(self.gateway)
        for key, value in request_data.items():
            result += """<input type="hidden" name="{0}" id="{0}" value="{1}"/>""".format(key, value)
        result = result + """<!-- <input type="submit" type="hidden">--></form></body></html>"""
        return result

    def pay_url(self, request_data):
        payment_url = "{}?{}".format(self.backend_url, parse.urlencode(request_data))
        return payment_url

    def verify_query(self, order_num, txn_time):
        """
        验证查询的交易状态
        :param order_num:
        :param txn_time:
        :return:
        """
        request_data = {
            "version": self.version,
            "encoding": "utf-8",
            "txnType": UnionTradeType.query,
            "txnSubType": "00",
            "bizType": "000201",
            "signMethod": "01",  # 签名方法  01：RSA签名
            "accessType": "0",
            "merId": self.mer_id,
            "txnTime": txn_time,
            "orderId": order_num,
            "certId": self.cert_id,
        }

        union_pay.get_sign(request_data)
        request_data["signature"] = parse.urlencode({'signature': request_data['signature']})[10:]
        req_string = union_pay.build_sign_str(request_data)

        res = requests.post(
            url=self.query_gateway,
            data=req_string,
            headers={
                "content-type": "application/x-www-form-urlencoded"
            }
        )
        if res.status_code != requests.codes.ok:
            query_status = False
        else:
            content = self.parse_arguments(res.content.decode("utf-8"))
            if content.get("origRespCode", "") == "00":
                query_status = True
            else:
                query_status = False
        return query_status

    def verify_sign(self, data):
        """
        银联回调签名校验
        """
        signature = data.pop('signature')  # 获取签名
        link_string = self.build_sign_str(data)
        digest = hashlib.sha256(bytes(link_string, encoding="utf-8")).hexdigest()
        signature = base64.b64decode(signature)
        sign_pubkey_cert = data.get("signPubKeyCert", None)

        try:
            x509_ert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, sign_pubkey_cert)
            OpenSSL.crypto.verify(x509_ert, signature, digest, 'sha256')
            return True
        except Exception as exc:
            return False

    def __get_cert_id(self, cert_path):
        """
        获取证书ID(签名KEY)
        :param cert_path:
        :return:
        """
        with open(cert_path, "rb") as f:
            certs = OpenSSL.crypto.load_pkcs12(f.read(), UnionPayConfig.cert_password)
            x509data = certs.get_certificate()
            self.cert["certid"] = x509data.get_serial_number()
            self.cert["pkey"] = certs.get_privatekey()

        return self.cert["certid"]

    @staticmethod
    def build_sign_str(data):
        """
        排序
        :param data:
        :return:
        """
        req = []
        for key in sorted(data.keys()):
            if data[key] != '':
                req.append("%s=%s" % (key, data[key]))

        return '&'.join(req)

    @staticmethod
    def parse_arguments(raw):
        """
        :param raw: raw data to parse argument
        :return:
        """
        data = {}
        qs_params = parse.parse_qs(str(raw))
        for name in qs_params.keys():
            data[name] = qs_params.get(name)[-1]
        return data


union_pay = UnionPay(
    UnionPayConfig.version,
    UnionPayConfig.mer_id,
    UnionPayConfig.front_url,
    UnionPayConfig.back_url,
    UnionPayConfig.back_url,
    UnionPayConfig.cert_path,
    debug=UnionPayConfig.debug,
)

if __name__ == '__main__':

    # 生成支付html直接 HttpResponse 渲染html即可跳转至银联支付网关
    pay_data = union_pay.build_request_data("12345678901", "1")
    pay_html = union_pay.pay_html(pay_data)
    print(pay_html)

    # 后台回调验证示例:
    # 此参数返回的是 后台回调地址返回的通知参数
    response = {
        'accNo': '6221********0000',
        'accessType': '0',
        'bizType': '000201',
        'currencyCode': '156',
        'encoding': 'utf-8',
        'merId': '777290058153361',  #
        'orderId': '324892347234800',  # 原交易的orderId
        'queryId': '201711120349542432648',  # 银联流水号
        'respCode': '00',  # 应答码 00表示交易成功
        'respMsg': '成功[0000000]',  # 应答信息
        'settleAmt': '1',  # 清算金额。境内商户同原交易的txnAmt。
        'settleCurrencyCode': '156',  # 清算币种。境内商户固定返回156。
        'settleDate': '1112',  # 清算日期
        'signMethod': '01',
        'signPubKeyCert': '-----BEGIN CERTIFICATE-----\r\nMIIEOjCCAyKgAwIBAgIFEAJkAUkwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMC\r\nQ04xMDAuBgNVBAoTJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhv\r\ncml0eTEXMBUGA1UEAxMOQ0ZDQSBURVNUIE9DQTEwHhcNMTUxMjA0MDMyNTIxWhcN\r\nMTcxMjA0MDMyNTIxWjB5MQswCQYDVQQGEwJjbjEXMBUGA1UEChMOQ0ZDQSBURVNU\r\nIE9DQTExEjAQBgNVBAsTCUNGQ0EgVEVTVDEUMBIGA1UECxMLRW50ZXJwcmlzZXMx\r\nJzAlBgNVBAMUHjA0MUBaMTJAMDAwNDAwMDA6U0lHTkAwMDAwMDA2MjCCASIwDQYJ\r\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMUDYYCLYvv3c911zhRDrSWCedAYDJQe\r\nfJUjZKI2avFtB2/bbSmKQd0NVvh+zXtehCYLxKOltO6DDTRHwH9xfhRY3CBMmcOv\r\nd2xQQvMJcV9XwoqtCKqhzguoDxJfYeGuit7DpuRsDGI0+yKgc1RY28v1VtuXG845\r\nfTP7PRtJrareQYlQXghMgHFAZ/vRdqlLpVoNma5C56cJk5bfr2ngDlXbUqPXLi1j\r\niXAFb/y4b8eGEIl1LmKp3aPMDPK7eshc7fLONEp1oQ5Jd1nE/GZj+lC345aNWmLs\r\nl/09uAvo4Lu+pQsmGyfLbUGR51KbmHajF4Mrr6uSqiU21Ctr1uQGkccCAwEAAaOB\r\n6TCB5jAfBgNVHSMEGDAWgBTPcJ1h6518Lrj3ywJA9wmd/jN0gDBIBgNVHSAEQTA/\r\nMD0GCGCBHIbvKgEBMDEwLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cuY2ZjYS5jb20u\r\nY24vdXMvdXMtMTQuaHRtMDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly91Y3JsLmNm\r\nY2EuY29tLmNuL1JTQS9jcmw0NDkxLmNybDALBgNVHQ8EBAMCA+gwHQYDVR0OBBYE\r\nFAFmIOdt15XLqqz13uPbGQwtj4PAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqG\r\nSIb3DQEBBQUAA4IBAQB8YuMQWDH/Ze+e+2pr/914cBt94FQpYqZOmrBIQ8kq7vVm\r\nTTy94q9UL0pMMHDuFJV6Wxng4Me/cfVvWmjgLg/t7bdz0n6UNj4StJP17pkg68WG\r\nzMlcjuI7/baxtDrD+O8dKpHoHezqhx7dfh1QWq8jnqd3DFzfkhEpuIt6QEaUqoWn\r\nt5FxSUiykTfjnaNEEGcn3/n2LpwrQ+upes12/B778MQETOsVv4WX8oE1Qsv1XLRW\r\ni0DQetTU2RXTrynv+l4kMy0h9b/Hdlbuh2s0QZqlUMXx2biy0GvpF2pR8f+OaLuT\r\nAtaKdU4T2+jO44+vWNNN2VoAaw0xY6IZ3/A1GL0x\r\n-----END CERTIFICATE-----',
        'traceNo': '243264',  # 系统跟踪号
        'traceTime': '1112034954',
        'txnAmt': '1',  # 交易金额
        'txnSubType': '01',  # 一般情况同原交易的txnSubType。当txnType为01时，如果txnSubType为03，表示这笔交易为分期交易。
        'txnTime': '20171112034954',  # 交易传输时间。（月月日日时时分分秒秒）24小时制收单机构对账时使用，该域透传了请求上送的txnTime。
        'txnType': '01',  # 原交易的txnType
        'version': '5.1.0',
        'signature': 'APXSimxYyvJGkOTy7Lo6ugAoPVoeBB6YbWHlWDnzJQ0s3CpVzhahqpYvkgpdw183YXV52odcrGRAF1V9WDHzokePuTTEJoTp6yfTyzAl1lZn7+7J/eN42axF/dhF4iNVvSj6aeT9ZpLEM7zx4N3CCVBrCn84V0NP6lXQvVxTev/I2RVf9G8fjYPMB9EtUPAhU86gAwaoGJllsBoEVd8kSvPsn0iX7GU5UeM+PnruvBvkH0z63hiRwId4hYp15+KiGFtNPFdJcDHvnaDDhCVnarbyrfrNs621ugcCCJADLbfKKZImex+1W2o5QYX6yUJViVgWhVst1j6M6JPvVqmykw=='
    }

    # 验证结果为True表示签名校验通过, 并对己方订单进行相关操作(并给银联返回 ok 即可)
    # 按理应该交易成功进行交易查询再次验证订单交易状态
    print(union_pay.verify_sign(response))

    # 查询接口校验, 订单查询接口
    res = union_pay.verify_query("20171110111717484", "20171113123630")
    print(res)


