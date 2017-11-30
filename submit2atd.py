import matd
import time
import logging
import sys
import requests

#
# Use this tool for testing only
# Use this tool to submit a single file to ATD
# The tool will wait for analysis to complete and then get the analysis report in JSON format
#

# This tool has been tested successfully with MATD v3.x and v4.x on MAC OS and Linux CentOS.
#
# Used for disable SSL Verify warning
requests.packages.urllib3.disable_warnings()

# check parameters - MATD_IPAddress UserID Password filepath

if len(sys.argv) != 5:
  print("Usage submit2atd.py ATD_IPAddress userID pwd filename")
  exit()



# Logging configuration
#logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


hostname='https://' + sys.argv[1]
username=sys.argv[2]
passwd=sys.argv[3]
filename=sys.argv[4]



# Create a MATD client 
client = matd.Client(hostname, verify_ssl=False)

try:  
  # login
  client.login(username, passwd)

  # get  profiles
  vmprofiles = client.vm_profiles()

  # Send file to MATD using 1st profile
  job = client.file_upload(vmprofiles[0]['vmProfileid'], filename)    

  if job > 9:
    print("File uploaded OK - JobId=%d" % job.subId)

  # wait for analysis to complete 
  time.sleep(1)
  tasks = client.task_list(job.subId)

  # Wait for all tasks to complete
  client.wait_tasks(tasks)

  for taskId in tasks:
    print('---------------------- Analysis Status ------------------------')
    print(client.task_status(taskId))


  for taskId in tasks:
    print('---------------------- Analysis Report ------------------------')
    print(client.task_report(taskId, 'json'))

finally:
  # Logout - user finally in case that something goes wrong before so we are not
  # leaving session live
  client.logout()


