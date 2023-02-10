import requests
import json
from datetime import datetime
import sys

headers = {}

def init_api(key):
    global headers
    if len(key) == 64:
        headers = {
            'x-apikey': key,
        }
    else:
        print(f"Error: invalid VirusTotal API key length", file=sys.stderr)

def add_args(parser):
   parser.add_argument("--vt", default=False, action="store_true", help="check virustotal")
   return parser

def get_vtinfo(fileinfo, args):
    vtinfo = {}
    if args.vt and headers != {}:
        hashsum = fileinfo.get_info()["SHA256"]
        report = get_report(hashsum)
        if report == None:
            return None
        elif report == '':
            vtinfo['Detection'] = 'Not Found'
        else:
            date = get_first_submission_date(report)
            if date != None:
                first_submission = get_submission(hashsum, date)
            vtinfo = extract_values(report, first_submission)
            if 'Filename' in vtinfo:
                fileinfo.add_filename(vtinfo['Filename'])
    return vtinfo

def get_report(h):
    global headers
    response = requests.get('https://www.virustotal.com/api/v3/files/' + h, headers=headers)
    if response.status_code == 200:
        return response.text
    elif response.status_code == 401:
        headers = {}
        print(f"Error: invalid VirusTotal API key", file=sys.stderr)
        return None
    return ''

def extract_values(report, submission):
    info = {}
    report_attributes = get_attributes(report)
    submission_attributes = get_attributes(submission)
    if 'date' in submission_attributes:
        info['FirstSubmission'] = str(datetime.fromtimestamp(submission_attributes['date'])) + ' UTC'
    if 'name' in submission_attributes:
        info['Filename'] = submission_attributes['name']
    if 'source_key' in submission_attributes and 'interface' in submission_attributes:
        info['SubmitterID'] = submission_attributes['source_key']
    if 'interface' in submission_attributes:
        info['SubmitterInterface'] = submission_attributes['interface']
    if 'country' in submission_attributes:
        info['SubmitterCountry'] = submission_attributes['country']
    if 'city' in submission_attributes and submission_attributes['city'] != '?':
        info['SubmitterCity'] = submission_attributes['city']
    if 'last_analysis_stats' in report_attributes \
    and 'harmless' in report_attributes['last_analysis_stats'] \
    and 'undetected' in report_attributes['last_analysis_stats'] \
    and 'suspicious' in report_attributes['last_analysis_stats'] \
    and 'malicious' in report_attributes['last_analysis_stats']:
        h = int(report_attributes['last_analysis_stats']['harmless']) + int(report_attributes['last_analysis_stats']['undetected']) 
        m = int(report_attributes['last_analysis_stats']['suspicious']) + int(report_attributes['last_analysis_stats']['malicious']) 
        info['Detection'] = '{}/{}'.format(m, h+m)
    if 'popular_threat_classification' in report_attributes and 'suggested_threat_label' in report_attributes['popular_threat_classification']:
        info['ThreatLabel'] = report_attributes['popular_threat_classification']['suggested_threat_label']
    return info

def get_attributes(j):
    d = json.loads(j)
    if 'data' in d:
        data = d['data']
        if 'attributes' in data:
            return data['attributes']

def get_first_submission_date(text):
    d = json.loads(text)
    if 'data' in d:
        data = d['data']
        if 'attributes' in data:
            attributes = data['attributes']
            if 'first_submission_date' in attributes:
                return attributes['first_submission_date']
    return None

def get_submission(_id, date):
    global headers
    response = requests.get('https://www.virustotal.com/api/v3/submissions/f-' + _id + '-' + str(date), headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        return None
