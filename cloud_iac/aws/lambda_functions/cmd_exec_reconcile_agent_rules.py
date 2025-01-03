import logging
import os
import sys
import json
import copy
import traceback
import boto3
from boto3.dynamodb.conditions import Attr


DEBUG = bool(int(os.getenv('DEBUG', '0')))
STANDARD_SG_RULES_IGNORE_STRINGS = [
    '0|TCP|2022|::/0',
    '0|TCP|2022|0.0.0.0/0',
    '0|TCP|22|::/0',
    '0|TCP|22|0.0.0.0/0',
    '1|-1|-1|::/0',
    '1|-1|-1|0.0.0.0/0',
]


logger = logging.getLogger(os.path.basename(__file__).replace('.py', ''))
for handler in logger.handlers[:]: 
    logger.removeHandler(handler)
logger.setLevel(logging.INFO)
if DEBUG is True:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
if DEBUG is True:
    ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Silence most of boto3 library logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

# Prevent duplicate log entries
logger.propagate = False


def scan_dynamodb_table(table_name, filter_expression=None, expression_attribute_values=None):
    # This code obtained via Google Gemini - Slightly modified, but seems to work ok
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    scan_kwargs = {}
    if filter_expression:
        scan_kwargs['FilterExpression'] = filter_expression
    if expression_attribute_values:
      scan_kwargs['ExpressionAttributeValues'] = expression_attribute_values
    try:
        response = table.scan(**scan_kwargs)
        items = response['Items']
        while 'LastEvaluatedKey' in response:
            scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_kwargs)
            items.extend(response['Items'])
        return items, None
    except Exception as e:
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
        return None, str(e)


def get_records_from_dynamodb(table_name: str, key_begins_with: str):
    logger.info('Getting records from table "{}" with key starting with "{}"'.format(table_name, key_begins_with))
    filter_expression = Attr('RecordKey').begins_with(key_begins_with)
    items, error = scan_dynamodb_table(table_name=table_name, filter_expression=filter_expression)
    if error is not None:
        logger.error(
            'Error while retrieving records with key starting with "{}": {}'.format(
                key_begins_with,
                error
            )
        )
        return None
    return items


def extract_records(event)->list:
    records = list()
    try:
        if 'Records' in event:
            for record in event['Records']:
                if 'body' in record:
                    records.append(json.loads(record['body']))
    except Exception as e:
        logger.error('Failed to parse event and extract records: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return records


def get_records(relay_id: str, key_begins_with:str)->list:
    final_key_begins_with = '{}:{}'.format(key_begins_with,relay_id)
    final_key_begins_with = final_key_begins_with.replace('::', ':')
    dynamo_db_records = get_records_from_dynamodb(
        table_name='cumulus-tunnel',
        key_begins_with='{}'.format(final_key_begins_with)
    )
    if dynamo_db_records is not None:
        logger.debug('dynamo_db_records: {}'.format(json.dumps(dynamo_db_records, default=str)))
    else:
        logger.error('None value returned for relay "{}". Skipping.'.format(relay_id))
        return dict()
    return dynamo_db_records


def get_latest_record(records: list)->dict:
    latest_record = dict()
    for record in records:
        if len(latest_record) == 0:
            latest_record = copy.deepcopy(record)
            logger.debug('Setting latest record: {}'.format(json.dumps(record, default=str)))
        else:
            if record['RecordTtl'] > latest_record['RecordTtl']:
                latest_record = copy.deepcopy(record)
                logger.debug('Found newer record: {}'.format(json.dumps(record, default=str)))
            else:
                logger.warning('Ignoring older record: {}'.format(json.dumps(record, default=str)))
    logger.debug('Final latest_record: {}'.format(json.dumps(latest_record, default=str)))
    return latest_record


def attempt_to_convert_str_to_dict(possible_json_data: str)->dict:
    try:
        return json.loads(possible_json_data)
    except:
        pass
    return None


def get_item_it(records: list, item_key_name: str)-> str:
    try:
        record = get_latest_record(records=records)
        record_value = attempt_to_convert_str_to_dict(possible_json_data=record['RecordValue'])
        return record_value[item_key_name]
    except Exception as e:
        logger.error('Failed to parse data: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return None


def get_instance_id_and_security_group(instance_id_records: list, security_group_records: list)->tuple:
    instance_id = None
    security_group_id = None
    try:
        instance_id = get_item_it(records=instance_id_records, item_key_name='InstanceId')
        security_group_id = get_item_it(records=security_group_records, item_key_name='SecurityGroupId')

    except Exception as e:
        logger.error('Failed to parse data: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return instance_id, security_group_id


def get_current_security_group_rules(group_id: str, next_token: str=None)->list:
    rules = list()
    try:
        filters = [
            {
                'Name': 'group-id',
                'Values': [
                    '{}'.format(group_id),
                ]
            },
        ]
        client = boto3.client('ec2')
        response = dict()
        if next_token is not None:
            response = client.describe_security_group_rules(Filters=filters,NextToken=next_token)
        else:
            response = client.describe_security_group_rules(Filters=filters)
        logger.debug('response: {}'.format(json.dumps(response, default=str)))
        if 'NextToken' in response:
            rules += get_current_security_group_rules(group_id=group_id, next_token=response['NextToken'])
        if 'SecurityGroupRules' in response:
            for rule_record in response['SecurityGroupRules']:
                rule = dict()
                rule['IsEgress'] = rule_record['IsEgress']
                rule['IpProtocol'] = rule_record['IpProtocol']
                rule['FromPort'] = rule_record['FromPort']
                rule['ToPort'] = rule_record['ToPort']
                if 'CidrIpv4' in rule_record:
                    rule['CIDR'] = rule_record['CidrIpv4']
                if 'CidrIpv6' in rule_record:
                    rule['CIDR'] = rule_record['CidrIpv6']
                if 'Description' in rule_record:
                    rule['Description'] = rule_record['Description']
                else:
                    rule['Description'] = None
                rules.append(rule)
    except Exception as e:
        logger.error('Failed to get rules for security group ID "{}": {}'.format(group_id, str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    return rules


def convert_current_security_group_rules_to_standard_list_of_strings(rules: list)->list:
    lines = list()
    for rule in rules:
        """
        INPUT: 

            {
                "IsEgress": true,
                "IpProtocol": "-1",
                "FromPort": -1,
                "ToPort": -1,
                "CIDR": "::/0",
                "Description": null
            }

        LINE:

            IsEgress | IpProtocol | Port | CIDR
            1|-1|-1|::/0
        """
        logger.debug('Evaluating Rule: {}'.format(json.dumps(rule, default=str)))
        if rule['FromPort'] != rule['ToPort']:
            logger.warning('Strange rule with from and to ports being different - ignoring for now')
            continue
        is_egress = 0
        if rule['IsEgress'] is True:
            is_egress = 1
        protocol = '{}'.format(rule['IpProtocol'])
        protocol = protocol.upper()
        port = rule['FromPort']
        cidr = ''
        if 'CIDR' in rule:
            cidr = rule['CIDR']
        if len(cidr) > 0:
            lines.append(
                '{}|{}|{}|{}'.format(
                    is_egress,
                    protocol,
                    port,
                    cidr,
                )
            )
        else:
            logger.warning('CIDR not defined - ignoring rule for now')
    logger.debug('lines: {}'.format(json.dumps(lines, default=str)))
    return lines


def current_agent_sg_rules_as_list_of_strings(current_rules: list, ignore_list: list=STANDARD_SG_RULES_IGNORE_STRINGS)->list:
    agent_rules = list()
    current_rule: str
    for current_rule in current_rules:
        if current_rule in ignore_list:
            logger.debug('Skipping a rule in the ignore list: {}'.format(current_rule))
            continue
        if current_rule.startswith('1:'):
            logger.debug('Skipping a rule that is an egress rule: {}'.format(current_rule))
            continue
        agent_rules.append(copy.deepcopy(current_rule))
    logger.debug('Current Security Group Rules: {}'.format(json.dumps(agent_rules, default=str)))
    return agent_rules


def convert_incoming_rules_to_standard_list_of_strings(rule_sets: list)->list:
    """
        "RuleSets": [
        {
            "Port": 8999,
            "PortType": "TCP",
            "SourceAddress": "9.9.9.9/32",
            "RuleName": "46b4bc525735b2069d9fc3938123c9b3d4a3a55a6fe61dd72e895eef2b6701e0"
        },
        {
            "Port": 8999,
            "PortType": "TCP",
            "SourceAddress": "aaaa:aaaa:aaaa:0:aaaa:aaaa:aaaa:aaaa/128",
            "RuleName": "a1c7cfe0ad4b9ec5527888b6a719a0e9c949ebfb9496b9b57232b9f2f92719b5"
        },
    """
    agent_rules = list()
    try:
        for rule in rule_sets:
            agent_rules.append(
                '0|{}|{}|{}'.format(
                    rule['PortType'],
                    rule['Port'],
                    rule['SourceAddress']
                )
            )
    except Exception as e:
        logger.error('Failed to convert incoming rules: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    logger.debug('Incoming Agent Rule Requirements: {}'.format(json.dumps(agent_rules, default=str)))
    return agent_rules


def build_ip_permissions_record(cidr_type: str, cidr_ip: str, ip_protocol: str, from_port: str, to_port: str)->list:
    """
    IpPermissions=[
        {
            'IpProtocol': 'string',
            'FromPort': 123,
            'ToPort': 123,
            
            'IpRanges': [
                {
                    'Description': 'string',
                    'CidrIp': 'string'
                },
            ],
            'Ipv6Ranges': [
                {
                    'Description': 'string',
                    'CidrIpv6': 'string'
                },
            ],
            
        },
    ],
    """
    field_ip_ranges_name = 'IpRanges'
    cidr_field_name = 'CidrIp'
    if cidr_type == 'ipv6':
        field_ip_ranges_name = 'Ipv6Ranges'
        cidr_field_name = 'CidrIpv6'
    ip_permissions = list()
    cidr_ranges = list()
    cidr_range_record = dict()
    cidr_range_record[cidr_field_name] = cidr_ip
    cidr_ranges.append(cidr_range_record)
    ip_permission_record = dict()
    ip_permission_record['IpProtocol'] = ip_protocol
    ip_permission_record['FromPort'] = int(from_port)
    ip_permission_record['ToPort'] = int(to_port)
    ip_permission_record[field_ip_ranges_name] = cidr_ranges
    ip_permissions.append(ip_permission_record)
    logger.debug('ip_permission_record: {}'.format(json.dumps(ip_permission_record, default=str)))
    return ip_permissions


def add_ingress_rule(group_id, ip_protocol, from_port, to_port, cidr_ip, cidr_type: str='ipv4'):
    try:
        ip_permissions = build_ip_permissions_record(
            cidr_type=cidr_type,
            cidr_ip=cidr_ip,
            ip_protocol=ip_protocol,
            from_port=from_port,
            to_port=to_port
        )
        ec2 = boto3.client('ec2')
        response = ec2.authorize_security_group_ingress(GroupId=group_id,IpPermissions=ip_permissions)
        logger.debug('response: {}'.format(response))
        return True, None
    except Exception as e:
        logger.error('Failed to add rule to security group "{}": {}'.format(group_id, str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
        return False, str(e)


def delete_ingress_rule(group_id, ip_protocol, from_port, to_port, cidr_ip, cidr_type: str='ipv4'):
    try:
        ip_permissions = build_ip_permissions_record(
            cidr_type=cidr_type,
            cidr_ip=cidr_ip,
            ip_protocol=ip_protocol,
            from_port=from_port,
            to_port=to_port
        )
        ec2 = boto3.client('ec2')
        response = ec2.revoke_security_group_ingress(GroupId=group_id,IpPermissions=ip_permissions)
        logger.debug('response: {}'.format(response))
        return True, None
    except Exception as e:
        logger.error('Failed to delete rule from security group "{}": {}'.format(group_id, str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
        return False, str(e)


def determine_desired_state(current_agent_rules: list, incoming_agent_rules:list)->dict:
    sg_actions = dict()
    sg_actions['Add'] = list()
    sg_actions['Delete'] = list()
    sg_actions['NoAction'] = list()

    # NEW rules required:
    for rule in incoming_agent_rules:
        if rule not in current_agent_rules:
            sg_actions['Add'].append(rule)

    # DELETE rules no longer required
    for rule in current_agent_rules:
        if rule not in incoming_agent_rules:
            sg_actions['Delete'].append(rule)
        else:
            sg_actions['NoAction'].append(rule)

    logger.info('CALCULATED ACTIONS: {}'.format(json.dumps(sg_actions, default=str)))
    return sg_actions


def prep_action_variables(action_line: str)->tuple:
    rule_type, protocol_type, port, cidr = action_line.split('|')
    cidr_type = 'ipv4'
    final_protocol_type = '{}'.format(protocol_type)
    final_protocol_type = final_protocol_type.lower()
    if ':' in cidr:
        cidr_type = 'ipv6'
    try:
        final_protocol_type = int(protocol_type)
    except:
        pass
    return rule_type, final_protocol_type, port, cidr, cidr_type


def process_actions(calculated_actions: dict, group_id:str):
    for action_line in calculated_actions['Delete']:
        rule_type, final_protocol_type, port, cidr, cidr_type = prep_action_variables(action_line=action_line)
        if rule_type == '1':
            logger.warning('Egress rules are not yet supported')
            continue
        result, error = delete_ingress_rule(
            group_id=group_id,
            ip_protocol=final_protocol_type,
            from_port=port,
            to_port=port,
            cidr_ip=cidr,
            cidr_type=cidr_type
        )
        logger.info('DELETE RULE ACTION: {} --> {} / {}'.format(action_line, result, error))
    for action_line in calculated_actions['Add']:
        rule_type, final_protocol_type, port, cidr, cidr_type = prep_action_variables(action_line=action_line)
        if rule_type == '1':
            logger.warning('Egress rules are not yet supported')
            continue
        result, error = add_ingress_rule(
            group_id=group_id,
            ip_protocol=final_protocol_type,
            from_port=port,
            to_port=port,
            cidr_ip=cidr,
            cidr_type=cidr_type
        )
        logger.info('NEW RULE ACTION: {} --> {} / {}'.format(action_line, result, error))


def relay_server_recon(event: dict):
    logger.info('==============================================')
    logger.info('===    Relay Server Security Group Recon   ===')
    logger.info('==============================================')
    for record in extract_records(event=event):
        logger.debug('Processing record: {}'.format(json.dumps(record, default=str)))
        instance_id_records = get_records(relay_id=record['TargetRelayId'], key_begins_with='relay-server:instance-id:')
        security_group_records = get_records(relay_id=record['TargetRelayId'], key_begins_with='relay-server:security-group:')
        if len(instance_id_records) == 0 or len(security_group_records) == 0:
            logger.error('No records for relay "{}" found. Skipping.'.format(record['TargetRelayId']))
            continue
        
        instance_id, security_group_id = get_instance_id_and_security_group(
            instance_id_records=instance_id_records,
            security_group_records=security_group_records
        )
        
        logger.info('Latest instance ID is "{}" with security group ID: "{}"'.format(instance_id, security_group_id))

        current_security_group_rules = get_current_security_group_rules(group_id=security_group_id)
        logger.debug('current_security_group_rules: {}'.format(json.dumps(current_security_group_rules, default=str)))

        current_agent_rules = current_agent_sg_rules_as_list_of_strings(
            current_rules=convert_current_security_group_rules_to_standard_list_of_strings(
                rules=current_security_group_rules
            ),
            ignore_list=STANDARD_SG_RULES_IGNORE_STRINGS
        )

        incoming_agent_rules = convert_incoming_rules_to_standard_list_of_strings(rule_sets=record['RuleSets'])

        calculated_actions = determine_desired_state(
            current_agent_rules=current_agent_rules,
            incoming_agent_rules=incoming_agent_rules
        )
        process_actions(calculated_actions=calculated_actions, group_id=security_group_id)


def create_alb_incoming_standard_rules(rule_sets: list)->list:
    agent_rules = list()
    try:
        for rule_record in rule_sets:
            source_address = rule_record['SourceAddress']
            for port in ('80', '443', '8081',):
                agent_rules.append(
                    '0|tcp|{}|{}'.format(
                        port,
                        source_address
                    )
                )
    except Exception as e:
        logger.error('Failed to convert incoming rules: {}'.format(str(e)))
        logger.debug('EXCEPTION: {}'.format(traceback.format_exc()))
    logger.debug('Incoming Agent Rule Requirements: {}'.format(json.dumps(agent_rules, default=str)))
    return agent_rules


def alb_recon(event:dict):
    logger.info('==============================================')
    logger.info('===        ALB Security Group Recon        ===')
    logger.info('==============================================')
    for record in extract_records(event=event):
        logger.debug('Processing record: {}'.format(json.dumps(record, default=str)))
        security_group_records = get_records(relay_id=record['TargetRelayId'], key_begins_with='relay-server:alb-security-group:')
        if len(security_group_records) == 0:
            logger.error('No records for relay "{}" found. Skipping.'.format(record['TargetRelayId']))
            continue
        security_group_id = get_item_it(records=security_group_records, item_key_name='SecurityGroupId')
        logger.info('Latest security group ID: "{}"'.format(security_group_id))
        current_security_group_rules = get_current_security_group_rules(group_id=security_group_id)
        logger.debug('current_security_group_rules: {}'.format(json.dumps(current_security_group_rules, default=str)))
        current_agent_rules = current_agent_sg_rules_as_list_of_strings(
            current_rules=convert_current_security_group_rules_to_standard_list_of_strings(
                rules=current_security_group_rules
            ),
            ignore_list=list()
        )
        incoming_agent_rules = create_alb_incoming_standard_rules(rule_sets=record['RuleSets'])
        calculated_actions = determine_desired_state(
            current_agent_rules=current_agent_rules,
            incoming_agent_rules=incoming_agent_rules
        )
        process_actions(calculated_actions=calculated_actions, group_id=security_group_id)


def handler(event, context):
    logger.debug('event: {}'.format(json.dumps(event, default=str)))
    relay_server_recon(event=event)
    alb_recon(event=event)
    

    return "ok"

