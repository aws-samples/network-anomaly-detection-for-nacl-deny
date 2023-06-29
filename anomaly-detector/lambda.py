#  Copyright 2016-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

"""Lambda function that maintains the lifecycle of NACL rules."""

import time
import os
import logging
from datetime import datetime
import calendar
import json
import boto3
import botocore

log = logging.getLogger()
log.setLevel(logging.INFO)

# ignore source IPs in VPC CIDR
VPC_CIDR = os.environ['VPC_CIDR']

# name of log group used for VPC flow logs
LOG_GROUP_NAME = os.environ['LOG_GROUP_NAME']

# only monitor traffic on this port
LISTENER_PORT = int(os.environ['LISTENER_PORT'])
LISTENER_PROTOCOL = int(os.environ['LISTENER_PROTOCOL'])

# only monitor traffic over this length of time (rolling window)
TIME_WINDOW_SECONDS = int(os.environ.get('TIME_WINDOW_SECONDS', '3600'))

# number of seconds for each packet bin
BIN_SECONDS = int(os.environ.get('BIN_SECONDS', '60'))

# don't block sources sending fewer than this number of packets
MIN_PACKETS_PER_BIN = int(os.environ.get('MIN_PACKETS_PER_BIN', '1000'))

# only consider blocking sources with a z-score at least this high
MIN_ZSCORE = float(os.environ.get('MIN_ZSCORE', '3.0'))

# 40 is a good limit if you are using results for NACL rules
MAX_ANOMALIES = int(os.environ.get('MAX_ANOMALIES', '40'))

# Timestream database and table
DATABASE_NAME = os.environ.get('DATABASE_NAME')
DATABASE_TABLE = os.environ.get('DATABASE_TABLE')

# SNS topic for publishing anomalous source IPs
ANOMALIES_TOPIC_ARN = os.environ.get('ANOMALIES_TOPIC_ARN')

# namespace used for CloudWatch metrics
METRICS_NAMESPACE = os.environ.get('METRICS_NAMESPACE')

# seconds to wait while checking CloudWatch query status
QUERY_WAIT_INTERVAL_SECONDS = 1

# max total seconds to wait while checking CloudWatch query status
MAX_QUERY_WAIT_SECONDS = 30

# format used for bins in CloudWatch query result
BIN_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

# only query for packet bins over this length of time
TIME_WINDOW_SECONDS_FOR_UPDATING_BINS = 300

# limit for number of records returned per CloudWatch query
QUERY_RECORDS_LIMIT = 10000

logs = boto3.client('logs')
cloudwatch = boto3.client('cloudwatch')
sns = boto3.client('sns')
write_client = boto3.client('timestream-write')
query_client = boto3.client('timestream-query')


def get_bin_time_sec(packet_bin):
    """Parse timestamp from string format used by CloudWatch bins."""
    bin_ts = datetime.strptime(packet_bin['bin_ts'], BIN_TIME_FORMAT)
    return calendar.timegm(bin_ts.utctimetuple())


def update_bin_time_series(packet_bins):
    """Update Timestream database with list of packet bins."""
    # create a new version of records that overwrites previous
    # bins that may only have partial information

    version = int(round(time.time() * 1000))

    def get_timestream_record(packet_bin):
        return {
            'Dimensions': [
              {
                'Name': 'source_ip',
                'Value': packet_bin['srcAddr']
              }
            ],
            'MeasureName': 'packets',
            'MeasureValue': packet_bin['packet_count'],
            'MeasureValueType': 'BIGINT',
            'Time': str(get_bin_time_sec(packet_bin) * 1000),
            'Version': version
        }

    # convert the packet bins into a format Timestream expects

    records = list(map(get_timestream_record, packet_bins))
    log.info('upserting %d packet bin records', len(records))

    # update the time series table in batches (Timestream supports
    # writing up to 100 records at a time)

    batch_size = 100
    for i in range(0, len(records), batch_size):
        params = {
            'DatabaseName': DATABASE_NAME,
            'TableName': DATABASE_TABLE,
            'Records': records[i:i + batch_size]
        }

        try:
            write_client.write_records(**params)
        except botocore.exceptions.ClientError as error:
            log.error('error while updating table: %s', DATABASE_TABLE)
            log.error(error)


def get_outlier_info(now_time):
    """Query Timestream to detect anomalous source IPs."""
    # determine the beginning of our time window, which is the very
    # beginning of the minute that occurred 5 minutes ago
    # e.g. if the time is 08:10:04 then our start time is 08:05:00

    offset = TIME_WINDOW_SECONDS + (now_time % BIN_SECONDS)
    start_ms = (now_time - offset) * 1000

    # calculate the average and standard deviation across all bins
    # during the past TIME_WINDOW_SECONDS (1 hour) then calculate
    # the Z-score for each bin and only return the bins that meet
    # thresholds for Z-score and packets

    query = (
        f'WITH zscores AS ( '  # nosec B608
        f'  WITH bin_stats AS ( '
        f'    SELECT AVG(measure_value::bigint) AS bin_avg, '
        f'           STDDEV_POP(measure_value::bigint) AS bin_stddev '
        f'    FROM "{DATABASE_NAME}"."{DATABASE_TABLE}" '
        f'    WHERE measure_name = \'packets\' AND '
        f'          time >= from_milliseconds({start_ms}) '
        f'  ) '
        f'  SELECT time, source_ip, measure_value::bigint as packets, '
        f'         (measure_value::bigint - bin_avg) / bin_stddev as zscore '
        f'  FROM "{DATABASE_NAME}"."{DATABASE_TABLE}", bin_stats '
        f'  WHERE time >= from_milliseconds({start_ms}) AND '
        f'        measure_name = \'packets\' '
        f') '
        f'SELECT source_ip, MAX(zscore) as max_zscore, '
        f'       MAX(packets) as max_packets '
        f'FROM zscores '
        f'WHERE zscore > {MIN_ZSCORE:.1f} AND '
        f'      packets > {MIN_PACKETS_PER_BIN:d} '
        f'GROUP BY source_ip '
        f'ORDER BY max_zscore desc '
        f'LIMIT {MAX_ANOMALIES:d} '
    )

    result = query_client.query(QueryString=query)

    # convert native Timestream result into a list of maps

    result_list = []
    columns = list(map(lambda c: c['Name'], result['ColumnInfo']))
    for row in result['Rows']:
        cell = {}
        for i in range(0, len(row['Data'])):
            cell[columns[i]] = row['Data'][i]['ScalarValue']
        result_list.append(cell)

    return result_list


def query_logs(start_time, query):
    """Summarize the most recent flow log records into packet bins."""
    # run a concurrent query for each bin within the time window
    # to ensure we can see up to 10,000 source IPs per bin

    num_queries = int(TIME_WINDOW_SECONDS_FOR_UPDATING_BINS / BIN_SECONDS)
    query_ids = []
    for i in range(0, num_queries):
        i_start_time = start_time + i * BIN_SECONDS
        i_end_time = start_time + (i + 1) * BIN_SECONDS - 1

        query_params = {
            'logGroupNames': [LOG_GROUP_NAME],
            'limit': QUERY_RECORDS_LIMIT,
            'startTime': i_start_time,
            'endTime': i_end_time,
            'queryString': query
        }

        try:
            query_start = logs.start_query(**query_params)
            query_ids.append(query_start['queryId'])
        except botocore.exceptions.ClientError as error:
            # stop running queries if we have hit the limit
            error_code = error.response['Error']['Code']
            if error_code == 'LimitExceededException':
                log.error('LimitExceededException: %s', LOG_GROUP_NAME)
                break

            raise error

    # poll for each query status until complete

    results = []
    remaining_seconds = MAX_QUERY_WAIT_SECONDS

    try:
        for query_id in query_ids:
            query_result = logs.get_query_results(queryId=query_id)
            while query_result['status'] != 'Complete':
                if remaining_seconds <= 0:
                    break

                remaining_seconds -= QUERY_WAIT_INTERVAL_SECONDS
                time.sleep(QUERY_WAIT_INTERVAL_SECONDS)
                query_result = logs.get_query_results(queryId=query_id)

            results.extend(query_result['results'])
    except botocore.exceptions.ClientError as error:

        log.error(error)

    # format the results into a list of maps

    def get_query_record_dict(r):
        result = dict()
        for item in r:
            result[item['field']] = item['value']
        return result

    return list(map(get_query_record_dict, results))


def get_packet_bins(start_time):
    """Find top talkers by querying CloudWatch Logs."""
    # ignore REJECT records so that blocked IPs don't pollute the baseline
    # ignore private source IPs

    query = (
        f'filter dstPort = {LISTENER_PORT:d} |'
        f'filter action = "ACCEPT" |'
        f'filter flowDirection = "ingress" |'
        f'filter protocol = {LISTENER_PROTOCOL:d} |'
        f'filter not isIpInSubnet(srcAddr, "{VPC_CIDR}") |'
        f'stats sum(packets) as packet_count '
        f'      by bin ({BIN_SECONDS:d}s) as bin_ts, srcAddr |'
        f'order by bin_ts desc |'
        f'limit {QUERY_RECORDS_LIMIT:d}'
    )

    return query_logs(start_time, query)


# pylint: disable=unused-argument
def handler(event, context):
    """Handle event from EventBridge rule."""
    metrics_ts = datetime.now()

    now_time = int(time.time())
    end_time = now_time - (now_time % BIN_SECONDS)
    start_time = end_time - TIME_WINDOW_SECONDS_FOR_UPDATING_BINS

    # get latest packet bins from CloudWatch Logs

    records = get_packet_bins(start_time)
    unique_source_ips = set(map(lambda r: r['srcAddr'], records))

    # update Timestream table

    update_bin_time_series(records)

    # find statistical anomalies

    outlier_info = get_outlier_info(now_time)
    log.info('outliers: %s', outlier_info)

    # publish message to SNS topic

    sns_message = json.dumps(outlier_info)
    sns.publish(TopicArn=ANOMALIES_TOPIC_ARN, Message=sns_message)

    # publish CloudWatch metrics

    cloudwatch.put_metric_data(
        Namespace=METRICS_NAMESPACE,
        MetricData=[
            {
                'MetricName': 'TimeWindow',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': LOG_GROUP_NAME
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': TIME_WINDOW_SECONDS,
                'Unit': 'Seconds',
                'StorageResolution': 1
            },
            {
                'MetricName': 'BinInterval',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': LOG_GROUP_NAME
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': BIN_SECONDS,
                'Unit': 'Seconds',
                'StorageResolution': 1
            },
            {
                'MetricName': 'MinPacketsPerBin',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': LOG_GROUP_NAME
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': MIN_PACKETS_PER_BIN,
                'Unit': 'Seconds',
                'StorageResolution': 1
            },
            {
                'MetricName': 'OutlierSourceIPs',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': LOG_GROUP_NAME
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': len(outlier_info),
                'Unit': 'Count',
                'StorageResolution': 1
            },
            {
                'MetricName': 'UniqueSourceIPs',
                'Dimensions': [
                    {
                        'Name': 'LogGroupName',
                        'Value': LOG_GROUP_NAME
                    }
                ],
                'Timestamp': metrics_ts,
                'Value': len(unique_source_ips),
                'Unit': 'Count',
                'StorageResolution': 1
            }
        ]
    )
