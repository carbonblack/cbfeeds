import hashlib
import hmac
import logging
import requests

_logger = logging.getLogger(__name__)

class ISightAPI(object):
    """
    Helper class for talking to iSIGHT Partners remote API.
    """
    @staticmethod
    def from_config(config):
        return ISightAPI(   config.iSightRemoteImportUrl,
                            config.iSightRemoteImportUsername,
                            config.iSightRemoteImportPassword,
                            config.iSightRemoteImportPublicKey,
                            config.iSightRemoteImportPrivateKey)

    def __init__(self, base_url, username, password, public_key, private_key):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.public_key = public_key
        self.private_key = private_key

        query = None
        hashed_query = hmac.new(private_key, query, hashlib.sha256).hexdigest()

        self.headers = {
            'X-Auth'		: public_key,
            'X-Auth-Hash'	: hashed_query,
            'Authorization' : self.__encode_user_creds(username, password)
        }

    def __encode_user_creds(self, user, passw):
        """
        Private function to setup some Basic Auth stuff...
        """
        return "Basic " + (user + ":" + passw).encode("base64").rstrip()

    def get_i_and_w(self, days_back_to_retrieve):
        """
        Retrieve a CSV file of data of all reports from (now-days_back_to_retrieve) until now.
        """
        params = {'daysBack': days_back_to_retrieve, 'days': days_back_to_retrieve}
        url = "%sreport/view/i_and_w" % (self.base_url)

        _logger.info("Connecting to remote API '%s' using params: %s" % (url, params))

        resp = requests.get(url, params=params, headers=self.headers)
        resp.raise_for_status()
        return resp.content

    def get_report(self, report_id, format='xml'):
        """
        Download a report in a particular format.
        """
        url = "%sreport/view/docid/%s" % (self.base_url, report_id)
        params = {'format':format}
        resp = requests.get(url, params=params, headers=self.headers)
        resp.raise_for_status()
        return resp.content
