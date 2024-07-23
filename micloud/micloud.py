# -----------------------------------------------------------
# Library to login to xiaomi cloud and manage devices.
#
# (C) 2020 Sammy Svensson
# (C) 2024 Daljeet Nandha
# Released under MIT License
# email sammy@ssvensson.se
# -----------------------------------------------------------

import json
import hashlib
import logging
import time, locale, datetime
import tzlocal
import requests

from micloud import miutils
from .miutils import get_session
from .micloudexception import MiCloudAccessDenied, MiCloudException


class MiCloud:
    def __init__(self, username=None, password=None, country=None):
        super().__init__()
        self.user_id =       None
        self.service_token = None
        self.session =       None
        self.ssecurity =     None
        self.cuser_id =      None
        self.pass_token =    None

        self.failed_logins = 0 

        self.locale = locale.getdefaultlocale()[0]

        timezone = datetime.datetime.now(tzlocal.get_localzone()).strftime('%z')
        timezone = "GMT{0}:{1}".format(timezone[:-2], timezone[-2:])
        self.timezone = timezone

        self.default_server = 'de' # Sets default server to Europe.
        self.username = username
        self.password = password
        self.country = country
        if not country:
            self.country = self.default_server

    def get_token(self):
        """Return the servie token if you have successfully logged in."""
        return self.service_token

    def _check_credentials(self):
        return (self.username and self.password)

    def login(self):
        """Login in to Xiaomi cloud.

        :return: True if login successful, False otherwise.
        """
        if not self._check_credentials():
            logging.error("You need to define username and password to log in")
            return False

        if self.user_id and self.service_token:
            return True

        logging.debug("Xiaomi logging in with userid %s", self.username)
        try:
            if self._login_request():
                self.failed_logins = 0
            else:
                self.failed_logins += 1
                logging.debug("Xiaomi cloud login attempt %s", self.failed_logins)
        except MiCloudException as e:
            logging.info("Error logging on to Xiaomi cloud (%s): %s", self.failed_logins, str(e))
            self.failed_logins += 1
            self.service_token = None
            if self.failed_logins > 10:
                logging.info("Repeated errors logging on to Xiaomi cloud. Cleaning stored cookies")
                self._init_session(reset=True)
            return False
        except MiCloudAccessDenied as e:
            logging.info("Access denied when logging on to Xiaomi cloud (%s): %s", self.failed_logins, str(e))
            self.failed_logins += 1
            self.service_token = None
            if self.failed_logins > 10:
                logging.info("Repeated errors logging on to Xiaomi cloud. Cleaning stored cookies")
                self._init_session(reset=True)
            raise e
        except:
            logging.exception("Unknown exception occurred!")
            return False

        return True

    def _login_request(self):
        try:
            self._init_session()
            sign = self._login_step1()
            if not sign.startswith('http'):
                location = self._login_step2(sign)
            else:
                location = sign # we already have login location

            response3 = self._login_step3(location)
            if response3.status_code == 403:
                raise MiCloudAccessDenied("Access denied. Did you set the correct api key and/or username?")
            elif response3.status_code == 200:
                logging.debug("Your service token: %s", self.service_token)
                return True
            else:
                logging.debug("request returned status '%s', reason: %s, content: %s", response3.status_code,
                    response3.reason, response3.text)
                raise MiCloudException(response3.status_code + response3.reason)
        except MiCloudAccessDenied as e:
            raise e
        except Exception as e:
            raise MiCloudException("Cannot logon to Xiaomi cloud: " + str(e))

    def _init_session(self, reset=False):
        if not self.session or reset:
            if self.session is not None:
                self.session.close()
            self.session = get_session()

    def _login_step1(self):
        logging.debug("Xiaomi login step 1")

        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        self.session.cookies.update({'userId': self.user_id if self.user_id else self.username})
        response = self.session.get(url)
        response_json = json.loads(response.text.replace("&&&START&&&", ""))

        logging.debug("Xiaomi login step 1 response code: %s", response.status_code)
        logging.debug("Xiaomi login step 1 response: %s", json.dumps(response_json))

        try:
            if "_sign" in response_json:
                sign = response_json["_sign"]
                logging.debug("Xiaomi login step 1 sign: %s", sign)
                return sign
            else:
                logging.debug("Xiaomi login _sign missing. Maybe still has login cookie.")
                return ""

        except Exception as e:
            raise MiCloudException("Error getting logon sign. Cannot parse response.", e)

    def _login_step2(self, sign):
        logging.debug("Xiaomi login step 2")

        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        post_data = {
            'sid': "xiaomiio",
            'hash': hashlib.md5(self.password.encode()).hexdigest().upper(),
            'callback': "https://sts.api.io.mi.com/sts",
            'qs': '%3Fsid%3Dxiaomiio%26_json%3Dtrue',
            'user': self.username,
            '_json': 'true'
        }
        if sign:
            post_data['_sign'] = sign

        response = self.session.post(url, data=post_data)
        response_json = json.loads(response.text.replace("&&&START&&&", ""))

        logging.debug("Xiaomi login step 2 response code: %s", response.status_code)
        logging.debug("Xiaomi login step 2 response: %s", json.dumps(response_json))

        if response_json['result'] != "ok":
            raise MiCloudAccessDenied("Access denied. Did you set the correct api key and/or username?")

        self.user_id = response_json['userId']
        self.ssecurity = response_json['ssecurity']
        self.cuser_id = response_json['cUserId']
        self.pass_token = response_json['passToken']

        location = response_json['location']
        code = response_json['code']

        logging.debug("Xiaomi login ssecurity: %s", self.ssecurity)
        logging.debug("Xiaomi login userId: %s", self.user_id)
        logging.debug("Xiaomi login cUserId: %s", self.cuser_id)
        logging.debug("Xiaomi login passToken: %s", self.pass_token)
        logging.debug("Xiaomi login location: %s", location)
        logging.debug("Xiaomi login code: %s", code)

        if location:
            return location
        else:
            raise MiCloudException("Error getting logon location URL. Return code: " + code)

    def _login_step3(self, location):
        logging.debug("Xiaomi login step 3 @ %s", location)

        self.session.headers.update({'content-type': 'application/x-www-form-urlencoded'})
        response = self.session.get(location)

        logging.debug("Xiaomi login step 3 content: %s", response.text)
        logging.debug("Xiaomi login step 3 status code: %s", response.status_code)

        service_token = response.cookies['serviceToken']
        if service_token:
            self.service_token = service_token

        return response

    def get_all_products(self):
        prods = json.loads(self._get_products())['result']
        return sorted(prods, key=lambda x: x['model'])

    def get_product_cats(self):
        cats = {prod['cate_name'] for prod in self.get_all_products()}
        return list(cats)

    def get_product_by_cat(self, cat):
        prods = [prod for prod in self.get_all_products()
                 if prod['cate_name'] == cat]
        return sorted(prods, key=lambda x: x['model'])

    def get_devices(self, raw=False, save=False, file="devices.json"):
        """Get a list with information about all devices.

        :param raw: Return raw result from server instead of a python list.
        :param save: Save information to json file. Default: False
        :param file: json file to save to.
        :return: List of devices
        :rtype: list
        """

        response = self._get_device_string()
        if not response:
            return None

        try:
            json_resp = json.loads(response)
            logging.debug('Devices data: %s', response)

            if save:
                f = open("devices.json", "w")
                f.write(json.dumps(json_resp['result'], indent=4, sort_keys=True))
                f.close()

            if raw:
                return response
            else:
                return json_resp['result']['list']
        except ValueError as e:
            logging.info("Error while parsing devices: %s", str(e))

    def get_version(self, did):
        """Get info about the latest firmware version.

        :param did: Device ID for which to fetch the info.
        """
        response = self._get_latest_ver(did)
        if not response:
            return None

        json_resp = json.loads(response)
        return json_resp['result']

    def bind(self, model, token=None, mac=None, bind_key=None):
        """Add a new device to user home.

        :param model: Model identifier, such as 'yeelink.light.nl1'
        """
        # if optional params are not set, use dummy value
        # server doesn't do any sanity check on these values :P
        if not token:
            token = "000000000000000000000000"
        if not mac:
            mac = "AA:AA:AA:AA:AA:AA"
        if not bind_key:
            bind_key = "00000000000000000000000000000000"

        resp1 = self._blt_apply_did(model, token, mac)
        resp2 = b"{}"
        res1 = json.loads(resp1)['result']
        if res1:
            resp2 = self._blt_bind(res1['did'], token, mac, bind_key)
        return {
            'model': model,
            'apply': json.loads(resp1),
            'bind': json.loads(resp2)
        }

    def delete(self, did, pid):
        """Delete a device from user home.

        :param did: Device ID to delete.
        :param pid: Product ID of the device.
        """
        return json.loads(self._del_device(did, int(pid)))

    def _blt_apply_did(self, model, token, mac):
        """This endpoint takes a model identifier and returns a did."""
        url = self._get_api_url() + "/device/bltapplydid"
        params = {
            "data": json.dumps({
                #"did": "blt.4.1ibur3721gg00"  # if 'did' is not given, server will generate
                "mac": mac,  # dummy value, not checked by server
                "model": model,
                "token": token
            })
        }
        try:
            resp = self.request(url, params)
            logging.debug("Get devices response: %s", resp)
            if len(resp) > 2:
                return resp
        except MiCloudException as e:
            logging.error("%s", str(e))
        return None

    def _blt_bind(self, did, token, mac, bind_key):
        """This endpoint takes a did and binds it to key, completes registration."""
        url = self._get_api_url() + "/device/bltbind"
        params = {
            "data": json.dumps({
                "did": did,
                "props": [
                    {
                        "key": "bind_key",
                        "type": "prop",
                        "value": bind_key
                    },
                    {
                        "key": "smac",
                        "type": "prop",
                        "value": mac
                    }
                ],
                "token": token
            })
        }
        try:
            resp = self.request(url, params)
            logging.debug("Get devices response: %s", resp)
            if len(resp) > 2:
                return resp
        except MiCloudException as e:
            logging.error("%s", str(e))
        return None

    def _del_device(self, did, pid):
        """This endpoint deletes a device from user home."""
        url = self._get_api_url() + "/user/del_owner_device_batch"
        params = {
            "data": json.dumps({
                "devList": [
                    {
                        "did": did,
                        "pid": pid
                    }
                ]
            })
        }
        try:
            resp = self.request(url, params)
            logging.debug("Del devices response: %s", resp)
            if len(resp) > 2:
                return resp
        except MiCloudException as e:
            logging.error("%s", str(e))
        return None

    def _get_device_string(self):
        """This endpoint returns a list of devices."""
        url = self._get_api_url() + "/home/device_list"
        params = {
            'data': '{"getVirtualModel":true,"getHuamiDevices":1,"get_split_device":false,"support_smart_home":true}'
        }
        try:
            resp = self.request(url, params)
            logging.debug("Get devices response: %s", resp)
            if len(resp) > 2:
                return resp
        except MiCloudException as e:
            logging.error("%s", str(e))
        return None

    def _get_latest_ver(self, did):
        """This endpoint returns the latest firmware version for a registered did."""
        url = self._get_api_url() + "/device/latest_ver"
        params = {
            'data': '{"did": "' + did + '"}'
        }
        try:
            resp = self.request(url, params)
            logging.debug("Get latest ver response: %s", resp)
            if len(resp) > 2:
                return resp
        except MiCloudException as e:
            logging.error("%s", str(e))
        return None

    def _get_products(self):
        """This endpoint returns the latest firmware version for a registered did."""
        url = self._get_api_url() + "/v2/productconfig/single_pull"
        params = {
            "data": json.dumps({
                "app_platform": "micloud",
                "app_version": 0,
                "keys": [
                    "cate_name",
                    "desc",
                    "name",
                ],
                "models": []
            })
        }
        try:
            resp = self.request(url, params)
            logging.debug("Get latest ver response: %s", resp)
            if len(resp) > 2:
                return resp
        except MiCloudException as e:
            logging.error("%s", str(e))
        return None

    def _get_api_url(self):
        return "https://" + ("" if self.country.strip().lower() == "cn" else self.country.strip().lower() + ".") + "api.io.mi.com/app"

    def request_country(self, url_part, country, params):
        url = self._get_api_url() + url_part
        response = self.request(url, params)
        logging.debug("Request to %s server %s. Response: %s", country, url_part, response)
        return response

    def request(self, url, params):
        if not self.service_token or not self.user_id:
            raise MiCloudException("Cannot execute request. service token or userId missing. Make sure to login.")

        logging.debug("Send request: %s to %s", params, url)

        self._init_session(reset=True)
        self.session.headers.update({
            'Accept-Encoding': 'identity',
            'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
            'content-type': 'application/x-www-form-urlencoded',
            'MIOT-ENCRYPT-ALGORITHM': 'ENCRYPT-RC4'
        })
        self.session.cookies.update({
            'userId': str(self.user_id),
            'yetAnotherServiceToken': self.service_token,
            'serviceToken': self.service_token,
            'locale': str(self.locale),
            'timezone': str(self.timezone),
            'is_daylight': str(time.daylight),
            'dst_offset': str(time.localtime().tm_isdst*60*60*1000),
            'channel': 'MI_APP_STORE'
        })
        for c in self.session.cookies:
            logging.debug('Cookie: %s', c)

        try:
            nonce = miutils.gen_nonce()
            signed_nonce = miutils.signed_nonce(self.ssecurity, nonce) 
            post_data = miutils.generate_enc_params(url, "POST", signed_nonce, nonce, params, self.ssecurity)

            response = self.session.post(url, data = post_data)
            if response.status_code == 403:
                self.service_token = None

            return miutils.decrypt_rc4(miutils.signed_nonce(self.ssecurity, post_data["_nonce"]), response.text)
        except requests.exceptions.HTTPError as e:
            self.service_token = None
            logging.exception("Error while executing request to %s :%s", url, str(e))
        except MiCloudException as e:
            logging.exception("Error while decrypting response of request to %s :%s", url, str(e))
        except Exception as e:
            logging.exception("Error while executing request to %s :%s", url, str(e))
