
import os
import logging
import time
from cbisight.isight_api import ISightAPI

_logger = logging.getLogger(__name__)

class ImporterDisabled(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class iSightLocalImporter(object):
    """
    Reads CSV files from a directory
    """
    def __init__(self, local_directory):
        """
        TODO
        """
        self.local_directory = local_directory

        if not self.local_directory:
            raise ImporterDisabled("iSightLocalImporter missing required field!")

        if not os.path.exists(local_directory):
            raise Exception("iSightLocalImporter specified directory not found!")

        self.processed_files = []

    def get_csv_data(self):
        """
        TODO
        """
        filepaths = os.listdir(self.local_directory)
        results = []
        for filepath in filepaths:
            if filepath.endswith('-processed'):
                continue
            try:
                full_filepath = os.path.join(self.local_directory, filepath)
                data = file(full_filepath, 'rb').read()
                results.append(data)
                self.processed_files.append(full_filepath)
            except:
                _logger.exception("Caught exception for: %s" % filepath)
        return results

    def on_processing_done(self):
        """
        We don't want to keep importing the same files (although presumably we protect
        against that with our database), so rename it after.
        """
        for filepath in self.processed_files:
            try:
                os.rename(filepath, filepath + "-processed")
            except:
                _logger.exception("Caught exception for: %s" % filepath)


class iSightRemoteImporter(object):
    """
    Basic API for downloading IOCs and Reports from iSight Partners
    """
    def __init__(self, base_url, username, password, public_key, private_key, days_back_to_retrieve, save_responses_directory):
        """
        TODO
        """
        if not base_url or \
            not username or \
            not password or \
            not public_key or \
            not private_key or \
            not days_back_to_retrieve:
            raise ImporterDisabled("iSightRemoteImporter missing required field(s)")

        self.api = ISightAPI(base_url, username, password, public_key, private_key)
        self.days_back_to_retrieve = days_back_to_retrieve
        self.save_responses_directory = save_responses_directory

    def get_csv_data(self):
        """
        Uses the iSight API Class to download the file, optionally save the response,
        and return the data.
        """
        rawcsv = self.api.get_i_and_w(self.days_back_to_retrieve)
        if len(rawcsv) > 0:
            if self.save_responses_directory and os.path.exists(self.save_responses_directory):
                try:
                    filename = "isight-remote-api-%s.csv" % time.strftime('%Y-%m-%d-%H_%M_%S', time.gmtime(time.time()))
                    file(os.path.join(self.save_responses_directory, filename), 'wb').write(rawcsv)
                except:
                    _logger.exception("Trying to save response!")
            return [rawcsv]
        else:
            _logger.error("Received blank response!")
            return []

    def on_processing_done(self):
        """
        Nothing to see here.
        """
        return
