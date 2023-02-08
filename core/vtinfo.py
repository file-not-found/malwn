import requests
import json
from datetime import datetime

headers = {}

def init_api(key):
    global headers
    headers = {
        'x-apikey': key,
    }

def add_args(parser):
   parser.add_argument("--vt", default=False, action="store_true", help="check virustotal")
   return parser

def get_vtinfo(fileinfo, args):
    vtinfo = None
    if args.vt:
        hashsum = fileinfo.get_info()["SHA256"]
        report = get_report(hashsum)
        if report == None:
            vtinfo = f"{hashsum} not found"
        else:
            date = get_first_submission_date(report)
            if date != None:
                first_submission = get_submission(hashsum, date)
            vtinfo = extract_values(report, first_submission)
    return vtinfo

def get_report(h):
    response = requests.get('https://www.virustotal.com/api/v3/files/' + h, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        return None

def extract_values(report, submission):
    info = {}
    report_attributes = get_attributes(report)
    submission_attributes = get_attributes(submission)
    if 'date' in submission_attributes:
        info['First Submission'] = str(datetime.fromtimestamp(submission_attributes['date'])) + ' UTC'
    if 'name' in submission_attributes:
        info['Filename'] = submission_attributes['name']
    if 'source_key' in submission_attributes and 'interface' in submission_attributes:
        info['Source'] = '{}-{}'.format(submission_attributes['source_key'], submission_attributes['interface'])
    if 'country' in submission_attributes:
        info['Country'] = submission_attributes['country']
    if 'city' in submission_attributes:
        info['City'] = submission_attributes['city']
    if 'last_analysis_stats' in report_attributes \
    and 'harmless' in report_attributes['last_analysis_stats'] \
    and 'undetected' in report_attributes['last_analysis_stats'] \
    and 'suspicious' in report_attributes['last_analysis_stats'] \
    and 'malicious' in report_attributes['last_analysis_stats']:
        h = int(report_attributes['last_analysis_stats']['harmless']) + int(report_attributes['last_analysis_stats']['undetected']) 
        m = int(report_attributes['last_analysis_stats']['suspicious']) + int(report_attributes['last_analysis_stats']['malicious']) 
        info['Detection'] = '{}/{}'.format(m, h+m)
    if 'popular_threat_classification' in report_attributes and 'suggested_threat_label' in report_attributes['popular_threat_classification']:
        info['Label'] = report_attributes['popular_threat_classification']['suggested_threat_label']
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
    response = requests.get('https://www.virustotal.com/api/v3/submissions/f-' + _id + '-' + str(date), headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        return None
