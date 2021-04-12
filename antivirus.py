import json
import requests
import json


scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
report_url = 'https://www.virustotal.com/vtapi/v2/file/report'


# this function takes the path to the file and then asks VirusTotal to scan it
def scanning(path_to_file):
    params = dict(apikey='your_key')
    path_to_file = path_to_file.split('/')
    scan_file = path_to_file[-1]
    files = {'file': (scan_file, open(scan_file, 'rb'))}
    response = requests.post(scan_url, files=files, params=params)
    if response.status_code == 200:
        scan_result = response.json()
        resource = scan_result['resource']
        return resource


# this function takes report
def report_info(resource):
    params = dict(apikey='your_key', resource=resource)
    report = requests.get(report_url, params=params)
    report_result = report.json()
    with open('report.json', 'w') as report_file:
        report_file.write(json.dumps(report_result))
    return json.dumps(report_result, sort_keys=False, indent=4)


# this function tells you if the file is malicious or not
def show_result():
    with open('report.json', 'r') as file:
        data = json.loads(file.read())
        malware = 0
        not_mal = 0
        for antivirus, result in data['scans'].items():
            answer = result.get('detected')
            if answer:
                malware += 1
            else:
                not_mal += 1
        if malware >= not_mal:
            print('This is malicious file.')
        else:
            print("This file is not malicious. So don't worry and live happy.")
