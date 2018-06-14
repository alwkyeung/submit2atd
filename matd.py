# This is REST API interface to work with ATD system
import base64
import sys
import logging
import requests
import json
import threading
import time

class MATDException(Exception):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return repr(self.value)

class Job(object):
  def __init__(self, json_data):
    self.success = json_data['success']
    self.subId = json_data['subId']
    self.tasks = []
    for task in json_data['results']:
      self.tasks.append(Task(task))

class Task(object):
  def __init__(self, json_task):
    self.taskId = json_task['taskId']
    self.file = json_task['file']
    self.md5 = json_task['md5']
    self.size = json_task['size']

class JobWaitThread(threading.Thread):
  def __init__(self, matd_client, jobId):
    threading.Thread.__init__(self)
    self.jobId = jobId
    self.matd_client = matd_client

  def run(self):
    self.data = None

    while True:
      logging.debug('---------------------------------------------------------')
      self.data = self.matd_client.job_status(self.jobId)

      if not self.data.get('success', False):
        return None

      status = self.data['status']

      if status == -1:
        logging.debug('status : failed')
        return self.data
      elif status == 0:
        logging.debug('status : submitted but taskId not generated')
      elif status == 2:
        logging.debug('status : waiting')
      elif status == 3:
        logging.debug('status : analyzing')
      elif status == 5:
        logging.debug('status : completed')
        return self.data
      else:
        logging.debug('Unsupported status {}'.format(status))
        return None

      time.sleep(5)

class BulkTaskWaitThread(threading.Thread):
  def __init__(self, matd_client, taskIds):
    threading.Thread.__init__(self)
    self.taskIds = taskIds
    self.matd_client = matd_client

  def run(self):
    self.data = None
    still_in_progress = True
    task_statuses = []
    while still_in_progress:
      logging.debug('------------------------------------------------------')
      task_statuses = self.matd_client.task_status_bulk(self.taskIds)

      if len(task_statuses) == 0:
        return None

      all_finished = True
      for task_status in task_statuses:        
        logging.debug("TASK %s", task_status)
        status = task_status['status']
        task_done = False
        if status == -1:
          logging.debug('status : failed')
          task_done = True
        elif status == 0:
          logging.debug('status : submitted but taskId not generated')
          task_done = False
        elif status == 2:
          logging.debug('status : waiting')
          task_done = False
        elif status == 3:
          logging.debug('status : analyzing')
        elif status == 5:
          logging.debug('status : completed')
          task_done = True
        else:
          logging.debug('Unsupported status {}'.format(status))
          task_done = True
        all_finished = all_finished and task_done

      still_in_progress = not all_finished
      time.sleep(5)
    self.data = task_statuses
    return self.data


class Client(object):
  HEADER_ACCEPT       = 'application/vnd.ve.v1.0+json'
  HEADER_CONTENT_JSON = 'application/json'

  SESSION_PATH      = '/php/session.php'
  FILE_UPLOAD_PATH  = '/php/fileupload.php'
  BRIEF_STATUS_PATH = '/php/samplestatus.php'
  VMPROFILES_PATH   = '/php/vmprofiles.php'
  REPORTS_PATH      = '/php/showreport.php'
  TASKLIST_PATH     = '/php/getTaskIdList.php'
  MD5VERIFY_PATH    = '/php/atdHashLookup.php'
  BULK_STATUS_PATH  = '/php/getBulkStatus.php'

  def __init__(self, url, verify_ssl=True):
    """
    MATD Client constructor.

    @param url: URL to MATD Server
    @param verify_ssl: Verify SSL certificate. Default M{True}

    Example:

    >>> import matd
    >>> client = matd.Client('https://14.21.139.74')

    """    
    self.url = url
    self.session_digest = None
    self.verify_ssl = verify_ssl

  def login(self, username, password):
    """
    MATD Login request.

    @param username: MATD username
    @param password: MATD password

    Example:

    >>> import matd
    >>> client = matd.Client('https://14.21.139.74')
    >>> client.login('john', 'password')
    >>> client.logout()
    
    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'Content-Type'    : Client.HEADER_CONTENT_JSON, 
      'VE-SDK-API'      : self.__encode_base64("{0}:{1}".format(username, password))
    }
    response = requests.post(self.__create_url(Client.SESSION_PATH), {}, headers=headers, verify=self.verify_ssl)
    self.__log_reponse(response)

    data = json.loads(response.text)

    if (self.__is_ok(data)):
      self.make_session(data['results']['session'], data['results']['userId'])
    else:
      raise MATDException(data['results'])

  def logout(self):
    """
    MATD Logout request

    B{Note : best is to use logout in try-finally block, once user is logged in session will still be alive
    and next login will fail.}

    Example:

    >>> import matd
    >>> client = matd.Client('https://14.21.139.74')
    >>> try:  
    >>>   client.login('john', 'password')
    >>>   # Do something here
    >>> finally:
    >>>   client.logout()
    
    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'Content-Type'    : Client.HEADER_CONTENT_JSON, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.delete(self.__create_url(Client.SESSION_PATH), headers=headers, verify=self.verify_ssl)
    self.__log_reponse(response)

  def vm_profiles(self):
    """
    Return list of VM Profiles

    Example:

    >>> import matd
    >>> client = matd.Client('https://14.21.139.74')
    >>> try:  
    >>>   print(client.vm_profiles())
    >>> finally:
    >>>   client.logout()
    
    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'Content-Type'    : Client.HEADER_CONTENT_JSON, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.get(self.__create_url(Client.VMPROFILES_PATH), headers=headers, verify=self.verify_ssl)
    self.__log_reponse(response)

    data = json.loads(response.text)

    if (self.__is_ok(data)):
      return data.get('results', [])
    else:
      return []

  def file_upload(self, profile_id, file_path):
    """
    Upload file to MATD

      @param profile_id: VM profile Id (see L{vm_profiles})
      @param file_path: path to file

      >>> try:  
      >>>   # Do login
      >>>   client.login('john', 'password')
      >>> 
      >>>   # Retrieve list of profiles
      >>>   vmprofiles = client.vm_profiles()
      >>> 
      >>>   # Send file to upload
      >>>   job = client.file_upload(vmprofiles[0]['vmProfileid'], 'Archive.zip')    
      >>> 
      >>>   # For some reasons task_list sometimes returns partial data (try to wait until all tasks are created)
      >>>   time.sleep(1)
      >>>   tasks = client.task_list(job.subId)
      >>> 
      >>>   # Wait for all tasks to complete
      >>>   client.wait_tasks(tasks)
      >>> 
      >>>   for taskId in tasks:
      >>>     print('---------------------- REPORT ------------------------')
      >>>     print(client.task_report(taskId, 'json'))
      >>> 
      >>> finally:
      >>>   client.logout()

    """    

    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'VE-SDK-API'      : self.session_digest
    }
    postdata = {'data': '{{"data":{{"xMode":0,"overrideOS":1,"messageId":"","vmProfileList":"{0}","submitType":"0","url":""}}}}'.format(profile_id) }
    file_up = {'amas_filename':open(file_path,'rb')}
    response = requests.post(self.__create_url(Client.FILE_UPLOAD_PATH),postdata,files=file_up,headers=headers,verify=False)    
    self.__log_reponse(response)

    data = json.loads(response.text)
    return Job(data)

  def task_list(self, jobId):
    """
      Retrieve list of tasks for specific job

      @param jobId: job id (or subId)

      >>> try:  
      >>>   # Do login
      >>>   client.login('john', 'password')
      >>> 
      >>>   # Retrieve list of profiles
      >>>   vmprofiles = client.vm_profiles()
      >>> 
      >>>   # Send file to upload
      >>>   job = client.file_upload(vmprofiles[0]['vmProfileid'], 'Archive.zip')    
      >>> 
      >>>   # For some reasons task_list sometimes returns partial data (try to wait until all tasks are created)
      >>>   time.sleep(1)
      >>>   tasks = client.task_list(job.subId)
      >>> 
      >>>   # Wait for all tasks to complete
      >>>   client.wait_tasks(tasks)
      >>> 
      >>>   for taskId in tasks:
      >>>     print('---------------------- REPORT ------------------------')
      >>>     print(client.task_report(taskId, 'json'))
      >>> 
      >>> finally:
      >>>   client.logout()

    """    

    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'Content-Type'    : Client.HEADER_CONTENT_JSON, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.get(self.__create_url(Client.TASKLIST_PATH) + '?jobId={0}'.format(jobId), headers=headers, verify=self.verify_ssl)
    self.__log_reponse(response)

    data = json.loads(response.text)

    if self.__is_ok(data):
      return list(map(int, data['result'].get('taskIdList', '').split(',')))
    else:
      return []

  def job_status(self, jobId):
    """
      Status of specific job

      @param jobId: job id (or subId)
    """    

    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'Content-Type'    : Client.HEADER_CONTENT_JSON, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.get(self.__create_url(Client.BRIEF_STATUS_PATH) + '?jobId={0}'.format(jobId), headers=headers, verify=self.verify_ssl)
    self.__log_reponse(response)

    return (response.text)

  def task_status(self, taskId):
    """
      Status of specific task

      @param taskId: task id
    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'Content-Type'    : Client.HEADER_CONTENT_JSON, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.get(self.__create_url(Client.BRIEF_STATUS_PATH) + '?iTaskId={0}'.format(taskId), headers=headers, verify=self.verify_ssl)
    self.__log_reponse(response)
    return (response.text)

  def job_status_bulk(self, jobIds):
    """
      Retrieve multiple statuses for list of jobs

      @param jobIds: array of jobs ids

    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'VE-SDK-API'      : self.session_digest
    }
    req_str = '{{"bulkrequest" : {{"numRequest" : "{0}", "jobIDs":{1}}}}}'.format(len(jobIds), str(jobIds))
    postdata = {'data':  req_str }
    response = requests.post(self.__create_url(Client.BULK_STATUS_PATH), postdata, headers=headers, verify=self.verify_ssl)    
    self.__log_reponse(response)

    data = json.loads(response.text)
    if (self.__is_ok(data)):
      return data['results']['bulkresponse']['status']
    else:
      return []

  def task_status_bulk(self, taskIds):
    """
      Retrieve multiple statuses for list of tasks

      @param taskIds: array of tasks ids

    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'VE-SDK-API'      : self.session_digest
    }
    req_str = '{{"bulkrequest" : {{"numRequest" : "{0}", "taskIDs":{1}}}}}'.format(len(taskIds), str(taskIds))
    postdata = {'data':  req_str }
    response = requests.post(self.__create_url(Client.BULK_STATUS_PATH), postdata, headers=headers, verify=self.verify_ssl)    
    #self.__log_reponse(response)

    data = json.loads(response.text)
    if (self.__is_ok(data)):
      return data['results']['bulkresponse']['status']
    else:
      return []

  def job_report(self, jobId, iType):
    """
      Retrieve report for specific job in different format types

      @param jobId: job id (subId)
      @param iType: type of report : html, txt, zip, json, ioc, stix, pdf

    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.post(self.__create_url(Client.REPORTS_PATH) + "?jobId={0}&iType={1}".format(jobId, iType), headers=headers, verify=self.verify_ssl)
    #self.__log_reponse(response)

    return response.text

  def task_report(self, taskId, iType):
    """
      Retrieve report for specific task in different format types

      @param taskId: task id
      @param iType: type of report : html, txt, zip, json, ioc, stix, pdf

    """    
    headers = { 
      'Accept'          : Client.HEADER_ACCEPT, 
      'VE-SDK-API'      : self.session_digest
    }
    response = requests.post(self.__create_url(Client.REPORTS_PATH) + "?iTaskId={0}&iType={1}".format(taskId, iType), headers=headers, verify=self.verify_ssl)
    #self.__log_reponse(response)

    return response.text

  def wait_job(self, jobId):
    """
      Wait current thread until job is finished

      @param jobId: job id (subId)

    """    
    thread = JobWaitThread(self, jobId)
    thread.start()
    thread.join()
    return thread.data

  def wait_tasks(self, taskIds):
    """
      Wait current thread until all tasks are finished

      @param taskIds: task id array

      >>> try:  
      >>>   # Do login
      >>>   client.login('john', 'password')
      >>> 
      >>>   # Retrieve list of profiles
      >>>   vmprofiles = client.vm_profiles()
      >>> 
      >>>   # Send file to upload
      >>>   job = client.file_upload(vmprofiles[0]['vmProfileid'], 'Archive.zip')    
      >>> 
      >>>   # For some reasons task_list sometimes returns partial data (try to wait until all tasks are created)
      >>>   time.sleep(1)
      >>>   tasks = client.task_list(job.subId)
      >>> 
      >>>   # Wait for all tasks to complete
      >>>   client.wait_tasks(tasks)
      >>> 
      >>>   for taskId in tasks:
      >>>     print('---------------------- REPORT ------------------------')
      >>>     print(client.task_report(taskId, 'json'))
      >>> 
      >>> finally:
      >>>   client.logout()
    """    
    thread = BulkTaskWaitThread(self, taskIds)
    thread.start()
    thread.join()
    return thread.data

  def make_session(self, session, user_id):
    """
      Create user session from session-id and user_id

      @param session: session string
      @param user_id: user id
    """

    self.session_digest = self.__encode_base64("{0}:{1}".format(session, user_id))

  def __create_url(self, path):
    return self.url + path

  def __is_ok(self, jdata):
    return jdata.get('success', False)

  def __log_reponse(self, response):
    #logging.info('Response [%i] [%s]', response.status_code, response.reason)
    #logging.info(response.text)
    return

  def __encode_base64(self, bytes_or_str):
    PY3 = sys.version_info
    if PY3 and isinstance(bytes_or_str, str):
      input_bytes = bytes_or_str.encode('utf8')
    else:
      input_bytes = bytes_or_str

    output_bytes = base64.urlsafe_b64encode(input_bytes)
    if PY3:
      return output_bytes.decode('ascii')
    else:
      return output_bytes
