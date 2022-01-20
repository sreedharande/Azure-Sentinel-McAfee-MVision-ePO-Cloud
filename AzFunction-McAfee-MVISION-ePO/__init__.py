import json
from datetime import datetime, timedelta
import os
import base64
import hashlib
import hmac
import requests
import threading
import logging
import re
import azure.functions as func



sentinel_customer_id = os.environ.get('WorkspaceID')
sentinel_shared_key = os.environ.get('WorkspaceKey')
sentinel_log_type = os.environ.get('LogAnalyticsCustomLogName')
logAnalyticsUri = os.environ.get('LAURI')

mvision_epo_userName = os.environ.get('MVision_ePO_UserName')
mvision_epo_password = os.environ.get('MVision_ePO_Password')
mvision_epo_token_url = os.environ.get('MVision_ePO_Token_Url')
mvision_epo_events_url = os.environ.get('MVision_ePO_Events_Url')
mvision_epo_client_id = os.environ.get('MVision_ClientID')
mvision_epo_scope = os.environ.get('MVision_Scope')
mvision_epo_event_type = os.environ.get('MVision_EventType') # threats, incidents (dlp), all
mvision_epo_event_limit = os.environ.get('MVision_EventsLimit')
mvision_epo_events_last_x_mins = os.environ.get('MVision_Events_Last_X_Mins')

# TODO: Read Collection schedule from environment variable as CRON expression; This is also Azure Function Trigger Schedule
collection_schedule = int(mvision_epo_events_last_x_mins)

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):    
    logAnalyticsUri = 'https://' + sentinel_customer_id + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern,str(logAnalyticsUri))
if(not match):
    raise Exception("Invalid Log Analytics Uri.")

def main(mytimer: func.TimerRequest) -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Starting program')
    file_events = 0
    failed_sent_events_number = 0
    successfull_sent_events_number = 0 

    mVision_ePO = McAfeeEPO(mvision_epo_token_url, mvision_epo_events_url, mvision_epo_userName, mvision_epo_password, mvision_epo_client_id, mvision_epo_scope)
    ts_from, ts_to = mVision_ePO.get_time_interval()

    logging.info('Retrieving McAfee MVISION ePO Events from {} to {}'.format(ts_from, ts_to))
    ePO_Events = mVision_ePO.get_events(ts_from, ts_to, mvision_epo_event_type, mvision_epo_event_limit)

    if ePO_Events is not None:
        for event in ePO_Events['Events']:
            sentinel = AzureSentinelConnector(logAnalyticsUri, sentinel_customer_id, sentinel_shared_key, sentinel_log_type, queue_size=10000, bulks_number=10)
            with sentinel:
                sentinel.send(event)
            file_events += 1 
            failed_sent_events_number += sentinel.failed_sent_events_number
            successfull_sent_events_number += sentinel.successfull_sent_events_number
    
        if failed_sent_events_number:
            logging.info('{} McAfee MVISION ePO Events have not been sent'.format(failed_sent_events_number))

        if successfull_sent_events_number:
            logging.info('Program finished. {} McAfee MVISION ePO Events have been sent.'.format(successfull_sent_events_number))

        if successfull_sent_events_number == 0 and failed_sent_events_number == 0:
            logging.info('No Fresh McAfee MVISION ePO Events')
    else:
        logging.info('Error in retrieving McAfee MVISION ePO Events')

class McAfeeEPO:
    def __init__(self, mVision_Token_Url, mVision_Events_Url, ePO_UserName, ePO_Password, mVision_ClientId, mVision_Scope):
        self.auth_url = mVision_Token_Url        
        self.base = mVision_Events_Url
        self.user = ePO_UserName
        self.pw = ePO_Password        
        self.client_id = mVision_ClientId
        self.scope = mVision_Scope

        headers = {'Accept': 'application/json'}

        self.session = requests.Session()
        self.session.headers = headers

        self.auth()

    def auth(self):
        data = {
            "username": self.user,
            "password": self.pw,
            "client_id": self.client_id,
            "scope": self.scope,
            "grant_type": "password"
        }

        res = requests.post(self.auth_url, data=data)
        if res.ok:
            token = res.json()['access_token']
            self.session.headers.update({'Authorization': 'Bearer ' + token})
            logging.info('Successfully authenticated.')
        else:
            logging.error('Could not authenticate. {0} - {1}'.format(str(res.status_code), res.text))            

    def get_time_interval(self):
        ts_now = datetime.utcnow()
        ts_nowiso = ts_now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'

        ts_past = ts_now - timedelta(minutes=collection_schedule)
        ts_pastiso = ts_past.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
        return ts_pastiso, ts_nowiso 

    def get_events(self, ts_pastiso, ts_nowiso, eventType, eventsLimit):
        params = {
            'type': eventType,  
            'since': ts_pastiso,
            'until': ts_nowiso,
            'limit': eventsLimit
        }

        res = self.session.get('{0}/eventservice/api/v2/events'.format(self.base), params=params)

        if res.ok:
            logging.info('Successfully retrieved MVISION EPO Events.')            
            return res.json()
        else:
            logging.error('Could not retrieve MVISION EPO Events. {0} - {1}'.format(str(res.status_code), res.text))           


class AzureSentinelConnector:
    def __init__(self, log_analytics_uri, customer_id, shared_key, log_type, queue_size=200, bulks_number=10, queue_size_bytes=25 * (2**20)):
        self.log_analytics_uri = log_analytics_uri
        self.customer_id = customer_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.queue_size = queue_size
        self.bulks_number = bulks_number
        self.queue_size_bytes = queue_size_bytes
        self._queue = []
        self._bulks_list = []
        self.successfull_sent_events_number = 0
        self.failed_sent_events_number = 0

    def send(self, event):
        self._queue.append(event)
        if len(self._queue) >= self.queue_size:
            self.flush(force=False)

    def flush(self, force=True):
        self._bulks_list.append(self._queue)
        if force:
            self._flush_bulks()
        else:
            if len(self._bulks_list) >= self.bulks_number:
                self._flush_bulks()

        self._queue = []

    def _flush_bulks(self):
        jobs = []
        for queue in self._bulks_list:
            if queue:
                queue_list = self._split_big_request(queue)
                for q in queue_list:
                    jobs.append(threading.Thread(target=self._post_data, args=(self.customer_id, self.shared_key, q, self.log_type, )))

        for job in jobs:
            job.start()

        for job in jobs:
            job.join()

        self._bulks_list = []

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self.flush()

    def _build_signature(self, customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
        return authorization

    def _post_data(self, customer_id, shared_key, body, log_type):
        events_number = len(body)
        body = json.dumps(body)      
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self._build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = self.log_analytics_uri + resource + '?api-version=2016-04-01'
        
        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri, data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            logging.info('{} events have been successfully sent to Azure Sentinel'.format(events_number))
            self.successfull_sent_events_number += events_number
        else:
            logging.error("Error during sending events to Azure Sentinel. Response code: {}".format(response.status_code))
            self.failed_sent_events_number += events_number

    def _check_size(self, queue):
        data_bytes_len = len(json.dumps(queue).encode())
        return data_bytes_len < self.queue_size_bytes

    def _split_big_request(self, queue):
        if self._check_size(queue):
            return [queue]
        else:
            middle = int(len(queue) / 2)
            queues_list = [queue[:middle], queue[middle:]]
            return self._split_big_request(queues_list[0]) + self._split_big_request(queues_list[1])
