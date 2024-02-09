from QualysAPI import QualysAPI
import csv
import argparse
from os.path import exists
from sys import exit
from getpass import getpass
import json
from xml.etree import ElementTree as ET


# Get the IDs of host names contained in list
def get_host_ids(hostnames: list, api: QualysAPI):
    print('INFO : Note: Assets without a QWEB Host ID will be excluded as there are is no vulnerability data for them')
    print(f'INFO : Getting Host IDs for {len(hostnames)} hosts.', end='')
    page_size = 1000
    offset = 1
    if len(hostnames) == 0:
        print('ERROR: get_host_ids - No hostnames in list')
        return None

    url = f'{api.server}/qps/rest/2.0/search/am/hostasset?fields=id,name,qwebHostId'
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-With': 'python/requests'}

    hosts = []
    more_data = True
    while more_data:
        service_request = {
            'ServiceRequest': {
                'preferences': {
                    'limitResults': page_size,
                    'startFromOffset': offset
                }
            }
        }

        response = json.loads(api.makeCall(url=url, headers=headers, payload=json.dumps(service_request),
                                           returnwith='text'))
        if response['ServiceResponse']['responseCode'] != 'SUCCESS':
            print('ERROR: get_host_ids - API Call Failed, aborting')
            exit(2)
        if response['ServiceResponse']['hasMoreRecords'] == 'false':
            more_data = False
        hosts += response['ServiceResponse']['data']
        offset += page_size
        print('.', end='')

    # With all the hostnames, use a little magic list comprehension to isolate the assets for which there
    # is a qwebHostId (meaning it has vulnerabilities) and where the hostname is in the target list
    ids = [ha['HostAsset']['qwebHostId']
           for ha in hosts
           if 'qwebHostId' in ha['HostAsset'].keys() and ha['HostAsset']['name'] in hostnames]
    print(' Done')
    return ids


def get_vulns(api: QualysAPI, ids: list, qds_min: int, qds_max: int):
    url = f'{api.server}/api/2.0/fo/asset/host/vm/detection/'
    vuln_payload = {
        'action': 'list',
        'ids': ','.join([str(id) for id in ids]),
        'show_qds': '1',
        'qds_min': str(qds_min),
        'qds_max': str(qds_max),
        'truncation_limit': '0'
    }
    headers = {'X-Requested-With': 'python/requests', 'Content-Type': 'application/x-www-form-urlencoded'}
    vuln_response = api.makeCall(url=url, payload=vuln_payload, method='POST', headers=headers)
    return vuln_response


# Script entry point
if __name__ == '__main__':
    password = ''
    use_proxy = False

    # Setup command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--input_file', help='CSV file containing hostnames to summarize')
    parser.add_argument('-u', '--user', help='Qualys username')
    parser.add_argument('-p', '--password', help='Qualys password, or \'-\' for safe interactive prompt')
    parser.add_argument('-a', '--api_url', help='Qualys API Base URL (e.g. https://qualysapi.qualys.com')
    parser.add_argument('-P', '--proxy_url', help='Proxy URL (optional)')
    parser.add_argument('-o', '--output_file', help='CSV output filename')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output for API calls')

    args = parser.parse_args()

    # Check passed arguments
    if args.input_file is None or args.input_file == '':
        print('ERROR: Input file not specified')
        exit(1)

    if not exists(args.input_file):
        print(f'ERROR: Input file {args.input_file} does not exist')
        exit(1)

    if args.user is None or args.user == '':
        print('ERROR: Qualys user not specified')
        exit(1)

    if args.password is None or args.password == '':
        print('ERROR: Qualys password not specified')
        exit(1)

    if args.password == '-':
        password = getpass(f'Enter password for {args.user} : ')
    else:
        password = args.password

    if args.api_url is None or args.api_url == '':
        print('ERROR: Qualys API Base URL not specified')
        exit(1)

    if args.proxy_url is not None:
        use_proxy = True

    if use_proxy:
        api = QualysAPI(svr=args.api_url, usr=args.user, passwd=password, enableProxy=True, proxy=args.proxy_url,
                        debug=args.debug)
    else:
        api = QualysAPI(svr=args.api_url, usr=args.user, passwd=password, debug=args.debug)

    # Main script body
    # Start with reading in the CSV file containing the hostnames
    hostnames = []
    print('INFO : Reading input file')
    with open(args.input_file, 'r') as inputfile:
        csvreader = csv.reader(inputfile, delimiter=',', quotechar='"')
        for row in csvreader:
            hostnames.append(row[0])

    # Next, we need to get the Host IDs for each of the hosts in the list.  This means getting the Host ID of ALL hosts
    # and then picking out the ones we want.
    # We can use the Asset Management & Tagging API to do this because it costs nothing.
    ids = get_host_ids(hostnames=hostnames, api=api)
    print(f'INFO : Got {len(ids)} Host IDs')

    # Next we can get the detections in the 4 different categories for the hosts
    print('INFO : Getting Critical vulnerability data')
    crit_results = get_vulns(api=api, ids=ids, qds_min=90, qds_max=100)
    print('INFO : Getting High vulnerability data')
    high_results = get_vulns(api=api, ids=ids, qds_min=70, qds_max=89)
    print('INFO : Getting Medium vulnerability data')
    med_results = get_vulns(api=api, ids=ids, qds_min=40, qds_max=69)
    print('INFO : Getting Low vulnerability data')
    low_results = get_vulns(api=api, ids=ids, qds_min=1, qds_max=39)

    # With all the data now in the results variables, we now process it and record the summaries against the assets
    # with a line for the totals.  We can use a dictionary to store the processed summary data, that will make it
    # easier to process and output later
    # That dictionary will look like this:
    # <qwebHostId>: {
    #   'name': <host name>,
    #   'hostId': <qwebHostId>,
    #   'critical': <number of crit vulns>
    #   'high': <number of high vulns>
    #   'medium': <number of medium vulns>
    #   'low': <number of low vulns>
    # }
    # and will be stored in a list
    vuln_data = []
    totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    print('INFO : Processing vulnerability data')
    for host in crit_results.findall('.//HOST'):
        hostId = host.find('ID').text
        hostname = host.find('DNS').text
        detection_count = len(host.findall('.//DETECTION'))
        if hostId not in [host['hostId'] for host in vuln_data]:
            host_vuln_data = {'name': hostname, 'hostId': hostId, 'critical': detection_count,
                              'high': 0, 'medium': 0, 'low': 0}
            vuln_data.append(host_vuln_data)
        else:
            [host for host in vuln_data if host['hostId'] == hostId][0]['critical'] = detection_count
        totals['critical'] += detection_count

    for host in high_results.findall('.//HOST'):
        hostId = host.find('ID').text
        hostname = host.find('DNS').text
        detection_count = len(host.findall('.//DETECTION'))
        if hostId not in [host['hostId'] for host in vuln_data]:
            host_vuln_data = {'name': hostname, 'hostId': hostId, 'high': detection_count,
                              'critical': 0, 'medium': 0, 'low': 0}
            vuln_data.append(host_vuln_data)
        else:
            [host for host in vuln_data if host['hostId'] == hostId][0]['high'] = detection_count
        totals['high'] += detection_count

    for host in med_results.findall('.//HOST'):
        hostId = host.find('ID').text
        hostname = host.find('DNS').text
        detection_count = len(host.findall('.//DETECTION'))
        if hostId not in [host['hostId'] for host in vuln_data]:
            host_vuln_data = {'name': hostname, 'hostId': hostId, 'medium': detection_count,
                              'high': 0, 'critical': 0, 'low': 0}
            vuln_data.append(host_vuln_data)
        else:
            [host for host in vuln_data if host['hostId'] == hostId][0]['medium'] = detection_count
        totals['medium'] += detection_count

    for host in low_results.findall('.//HOST'):
        hostId = host.find('ID').text
        hostname = host.find('DNS').text
        detection_count = len(host.findall('.//DETECTION'))
        if hostId not in [host['hostId'] for host in vuln_data]:
            host_vuln_data = {'name': hostname, 'hostId': hostId, 'low': detection_count,
                              'high': 0, 'medium': 0, 'critical': 0}
            vuln_data.append(host_vuln_data)
        else:
            [host for host in vuln_data if host['hostId'] == hostId][0]['low'] = detection_count
        totals['low'] += detection_count

    # Finally we output the data into a CSV file
    file_elements = args.output_file.split('.')
    if len(file_elements) == 1:
        output_file_name = f'{args.output_file}.csv'
    elif file_elements[len(file_elements)-1] != 'csv':
        output_file_name = f'{args.output_file}.csv'
    else:
        output_file_name = args.output_file

    print(f'INFO : Writing output file {output_file_name}')
    with open(output_file_name, 'w', newline='') as output_file:
        csv_output = csv.writer(output_file, delimiter=',', quotechar='"')
        csv_output.writerow(['Hostname', 'Critical', 'High', 'Medium', 'Low'])
        for host in vuln_data:
            csv_output.writerow([host['name'], host['critical'], host['high'], host['medium'], host['low']])
        csv_output.writerow(['TOTAL', totals['critical'], totals['high'], totals['medium'], totals['low']])

    output_file.close()
    exit(0)
