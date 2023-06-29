#  Copyright 2016-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

"""Lambda function that maintains the lifecycle of NACL rules."""

import os
import logging
import json
from datetime import datetime
from ipaddress import IPv4Network
from ipaddress import IPv4Address
import boto3
import botocore

log = logging.getLogger()
log.setLevel(logging.INFO)

# S3 bucket that contains allow list
ALLOW_LIST_BUCKET = os.environ.get('ALLOW_LIST_BUCKET', None)

# S3 object that contains allow list
ALLOW_LIST_KEY = os.environ.get('ALLOW_LIST_KEY', None)

# Name of the log group used for flow logs
FLOW_LOG_LOG_GROUP = os.environ['FLOW_LOG_LOG_GROUP']

# Name of the log group used for logging NACL rules
NACL_LOG_GROUP = os.environ['NACL_LOG_GROUP']

# Name of the log group used for logging NACL rules
NACL_LOG_STREAM = os.environ['NACL_LOG_STREAM']

# set this to the NACL rule limit
MAX_NACL_RULES = int(os.environ.get('MAX_NACL_RULES', '20'))

# comma-separated list of subnet ids
SUBNET_IDS = os.environ['SUBNET_IDS'].split(',')

# only monitor traffic on this port
LISTENER_PORT = int(os.environ['LISTENER_PORT'])

# namespace used for CloudWatch metrics
METRICS_NAMESPACE = os.environ.get('METRICS_NAMESPACE', 'AutoNACL')

# the two NACLs we alternate between
NETWORK_ACL_BLUE = os.environ.get('NETWORK_ACL_BLUE')
NETWORK_ACL_GREEN = os.environ.get('NETWORK_ACL_GREEN')

s3 = boto3.client('s3')
ec2 = boto3.client('ec2')
cloudwatch = boto3.client('cloudwatch')
logs = boto3.client('logs')


def get_allowed_networks(bucket, key):
    """Read and process the allow-list from S3."""
    # pylint: disable=broad-exception-caught

    params = {
        'Bucket': bucket,
        'Key': key
    }

    try:
        obj = s3.get_object(**params)['Body']
    except botocore.exceptions.ClientError as error:
        log.error(error)
        return set()

    def get_network(line):
        try:
            return IPv4Network(line.decode().strip())
        except ValueError:
            log.error('not a valid IP network: %s', line)

        return None

    def is_line(line):
        # igore empty lines and comments
        clean_line = line.decode().strip()
        return not (clean_line.startswith('#') or not clean_line)

    clean_lines = filter(is_line, obj.readlines())
    return set(map(get_network, clean_lines))


def filter_allowed_networks(ips, allowed):
    """Remove allowed networks from the list of IP addresses."""

    def include(ip_info):
        """Return true if provided IP address is not in allow-list."""
        for network in allowed:
            ip_address = None
            try:
                ip_address = IPv4Address(ip_info['source_ip'])
            except ValueError:
                log.error('not a valid IP address: %s', ip_info['source_ip'])

            if ip_address in network:
                return False

        return True

    return list(filter(include, ips))


def update_nacl(nacl_id, source_ips, port):
    """Replace existing NACL deny rule with new ones."""
    # template for creating NACL deny rules

    nacl_rule = {
        'Egress': False,
        'NetworkAclId': nacl_id,
        'CidrBlock': None,
        'PortRange': {'From': port, 'To': port},
        'Protocol': '-1',
        'RuleAction': 'deny',
        'RuleNumber': None
    }

    # find the existing NACL ingress rules

    filters = [
        {
            'Name': 'network-acl-id',
            'Values': [nacl_id]
        }
    ]

    try:
        nacls = ec2.describe_network_acls(Filters=filters)['NetworkAcls']
    except botocore.exceptions.ClientError as error:
        log.error(error)
        return

    if len(nacls) == 0:
        log.error('NACL not found: %s', nacl_id)
        return

    nacl = nacls[0]
    ingress_rules = list(filter(lambda x: not x['Egress'], nacl['Entries']))

    # delete all rules except default allow (100) and default deny (32767)

    log.info('removing %d NACL rules from %s', len(ingress_rules) - 2, nacl_id)
    for rule in ingress_rules:
        rule_number = rule['RuleNumber']
        if rule_number in (100, 32767):
            continue

        try:
            ec2.delete_network_acl_entry(Egress=False, NetworkAclId=nacl_id,
                                         RuleNumber=rule_number)
        except botocore.exceptions.ClientError as error:
            log.error(error)
            return

    # create new rules (starting at 1) for each source IP

    log.info('adding %d NACL rules to %s', len(source_ips), nacl_id)
    for i, ip_info in enumerate(source_ips, start=1):
        nacl_rule['CidrBlock'] = f'{ip_info["source_ip"]}/32'
        nacl_rule['RuleNumber'] = i

        try:
            ec2.create_network_acl_entry(**nacl_rule)
        except botocore.exceptions.ClientError as error:
            # stop adding rules if we have hit the limit for NACL rules
            error_code = error.response['Error']['Code']
            if error_code == 'NetworkAclEntryLimitExceeded':
                log.error('NetworkAclEntryLimitExceeded: %s', nacl_id)
                break

            raise error


def get_source_ips_from_sns_event(event):
    """Merge all source IPs from every record in event from SNS topic."""
    source_ips = []
    for record in event.get('Records', None):
        if record.get('EventSource', None) != 'aws:sns':
            log.warning('skipping non-SNS EventSource')
            continue

        sns_message = record.get('Sns', None)
        if not sns_message:
            log.warning('skipping non-SNS record')
            continue

        ips = json.loads(sns_message.get('Message', []))
        source_ips.extend(ips)

    return source_ips


def swap_nacls(current_nacl, blocked_source_ips, port):
    """Swap the NACL associated with each subnet."""
    # determine if we should use blue or green NACL

    current_nacl_id = current_nacl['NetworkAclId']
    if current_nacl_id == NETWORK_ACL_BLUE:
        new_nacl_id = NETWORK_ACL_GREEN
    else:
        new_nacl_id = NETWORK_ACL_BLUE

    # replace existing rules with new ones

    update_nacl(new_nacl_id, blocked_source_ips, port)

    # only update the association to subnets we care about

    associations = filter(lambda a: a['SubnetId'] in SUBNET_IDS,
                          current_nacl['Associations'])

    # swap the current NACL with the new one

    for association in associations:
        params = {
            'AssociationId': association['NetworkAclAssociationId'],
            'NetworkAclId': new_nacl_id
        }

        try:
            ec2.replace_network_acl_association(**params)
        except botocore.exceptions.ClientError as error:
            log.error('error while swapping NACL: %s', current_nacl)
            raise error


def log_ips(ip_infos, timestamp):
    """Log list of IP addresses to NACL log group."""
    if not ip_infos:
        return

    def get_record(ip_info):
        record = {
            'ip': ip_info['source_ip'],
            'z_score': round(float(ip_info['max_zscore']), 2),
            'packets': int(ip_info['max_packets'])
        }

        return {
            'timestamp': timestamp,
            'message': json.dumps(record)
        }

    params = {
        'logGroupName': NACL_LOG_GROUP,
        'logStreamName': NACL_LOG_STREAM,
        'logEvents': list(map(get_record, ip_infos))
    }

    try:
        logs.put_log_events(**params)
    except botocore.exceptions.ClientError as error:
        log.error('unable to write to log group: %s', NACL_LOG_GROUP)
        log.error(error)


# pylint: disable=unused-argument
def handler(event, context):
    """Respond to SNS event containing list of anomalous source IPs."""
    metrics_ts = datetime.now()

    source_ips = get_source_ips_from_sns_event(event)

    # sort the source IPs by descending zscore

    def get_zscore(ip_info):
        return float(ip_info['max_zscore'])

    source_ips = sorted(source_ips, key=get_zscore, reverse=True)

    # remove source IPs that are allowed

    if ALLOW_LIST_BUCKET and ALLOW_LIST_KEY:
        log.info('excluding source IPs defined in allow list')
        allowed = get_allowed_networks(ALLOW_LIST_BUCKET,
                                       ALLOW_LIST_KEY)
        source_ips = filter_allowed_networks(source_ips, allowed)

    # the default allow and default deny rules count against the limit

    max_rules = MAX_NACL_RULES - 2
    blocked_source_ips = source_ips[:max_rules]
    unblocked_source_ips = source_ips[max_rules:]

    # find the current NACL

    params = {
        'Filters': [
            {
                'Name': 'association.subnet-id',
                'Values': SUBNET_IDS
            }
        ]
    }
    nacls = ec2.describe_network_acls(**params)['NetworkAcls']
    current_nacl = nacls[0]

    # if the current NACL only has the 2 default rules and there
    # are no source IPs to deny then we don't need to swap NACLs

    def is_ingress(rule):
        return not rule['Egress']

    ingress_rules = list(filter(is_ingress, current_nacl['Entries']))
    if len(source_ips) == 0 and len(ingress_rules) == 2:
        log.info('nothing to do; exiting')
    else:
        swap_nacls(current_nacl, blocked_source_ips, LISTENER_PORT)

        log_timestamp = int(1000 * datetime.timestamp(metrics_ts))
        log_ips(blocked_source_ips, log_timestamp)

    # publish CloudWatch metrics

    cloudwatch.put_metric_data(
        Namespace=METRICS_NAMESPACE,
        MetricData=[
            {
                'MetricName': 'BlockedSourceIPs',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': FLOW_LOG_LOG_GROUP
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': len(blocked_source_ips),
                'Unit': 'Count',
                'StorageResolution': 1
            },
            {
                'MetricName': 'UnblockedSourceIPs',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': FLOW_LOG_LOG_GROUP
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': len(unblocked_source_ips),
                'Unit': 'Count',
                'StorageResolution': 1
            }
        ]
    )
