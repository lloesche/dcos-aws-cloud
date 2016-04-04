#!/usr/bin/env python3
import boto3
import time
import yaml
import botocore.exceptions
import logging
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

log_level = logging.INFO
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('DCOSStack').setLevel(log_level)
logging.getLogger('DCOSAuth').setLevel(log_level)
logging.getLogger('DNSAlias').setLevel(log_level)
logging.getLogger('requests').setLevel(log_level)
log = logging.getLogger(__name__)


def main():
    """Entry point

    Loads the file clusters.yaml and processes all the defined cluster stacks.
    Processing means it either creates or updates the stack to match it's specification.
    After that it checks that the default bootstrap user no longer exists and that the
    admin user has been created.
    """
    if len(sys.argv) > 1:
        clusters_file = sys.argv[1]
    else:
        clusters_file = 'clusters.yaml'
    log.debug("reading {}".format(clusters_file))
    clusters = yaml.load(open(clusters_file).read())

    admin_addr = None
    pubagt_addr = None
    dns_alias = DNSAlias()

    for cluster in clusters:
        for stack in cluster['Stacks']:
            dcos_stack = DCOSStack(stack)
            dcos_stack.process_stack()

            if not admin_addr:
                admin_addr = dcos_stack.admin_addr
            if not pubagt_addr:
                pubagt_addr = dcos_stack.pubagt_addr

        if admin_addr:
            dcos_auth = DCOSAuth('https://' + admin_addr, cluster['Admin'], cluster['AdminPassword'], 'Admin')
            dcos_auth.check_login()

        if cluster['DNS']:
            if admin_addr and cluster['DNS']['MasterAlias']:
                dns_alias.create(cluster['DNS']['MasterAlias'], admin_addr)
            if pubagt_addr and cluster['DNS']['PubAgentAlias']:
                dns_alias.create(cluster['DNS']['PubAgentAlias'], pubagt_addr)


class DNSAlias:
    """Create a DNS CNAME"""
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.r53 = boto3.client('route53')
        self.hosted_zones = []
        self.blacklist = ['mesosphere.com',
                          'mesosphere.io',
                          'downloads.mesosphere.io',
                          'repos.mesosphere.com',
                          'docs.mesosphere.com',
                          'open.mesosphere.com'
                          ]

    def create(self, hostnames, target):
        """Create a DNS alias (CNAME or Alias)

        :rtype: None
        :param hostnames: list or string of the DNS alias to create
        :param target: DNS name the hostname(s) should point to
        """
        if isinstance(hostnames, list):
            for hostname in hostnames:
                self.create_cname(hostname, target)
        else:
            self.create_cname(hostnames, target)

    def create_cname(self, hostname, target):
        """Create a CNAME

        :rtype: bool
        :param hostname: Hostname to create a CNAME for
        :param target: String the CNAME should point to
        :return:
        """
        self.log.info('creating CNAME from {} to {}'.format(hostname, target))
        if hostname in self.blacklist:
            self.log.warn('hostname {} is blacklisted'.format(hostname))
            return False

        src_zone_id = self.zone_id(hostname)
        if not src_zone_id:
            self.log.warn("hostname {} is not in a R53 hosted zone".format(hostname))
            return False

        r = self.r53.change_resource_record_sets(
            HostedZoneId=src_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': hostname,
                            'Type': 'CNAME',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': target
                                }
                            ]
                        }
                    }
                ]
            })
        if r:
            self.log.debug("submitted change request with ID {} status is {}".format(r['ChangeInfo']['Id'], r['ChangeInfo']['Status']))
            return True
        else:
            return False

    @property
    def zones(self):
        """Return the list of R53 hosted zones

        :rtype: list
        :return: List of zones
        """
        if len(self.hosted_zones) < 1:
            self.fetch_zones()
        return self.hosted_zones

    def fetch_zones(self):
        """Fetch the list of R53 hosted zones

        :rtype: None
        """
        self.log.debug('refreshing list of zones')
        complete = False
        next_marker = None
        zones = []

        while not complete:
            if next_marker:
                hz = self.r53.list_hosted_zones(Marker=next_marker)
            else:
                hz = self.r53.list_hosted_zones()

            zones.extend(hz['HostedZones'])

            if hz['IsTruncated']:
                next_marker = hz['NextMarker']
            else:
                complete = True

        self.hosted_zones = zones  # swap the list

    def zone_id(self, hostname, fuzzy=True):
        """Returns the R53 zone id of a given hostname

        :rtype: Union[str, None]
        :param hostname: DNS name for which to find the R53 zone ID
        :param fuzzy: bool whether to match the exact hostname or just the end of it
        :return:
        """
        self.log.debug('searching for zone ID of {}'.format(hostname))
        if not hostname.endswith('.'):
            hostname += '.'
        for z in self.zones:
            if fuzzy:
                if hostname.endswith(z['Name']):
                    self.log.debug('zone {} with id {} is a match for {}'.format(z['Name'], z['Id'], hostname))
                    return z['Id']
            else:
                if hostname == z['Name']:
                    self.log.debug('zone {} with id {} is a match for {}'.format(z['Name'], z['Id'], hostname))
                    return z['Id']
        self.log.debug('no matching zone found for {}'.format(hostname))


class DCOSStack:
    """Represents an AWS DCOS stack"""
    def __init__(self, settings):
        """Constructor

        :rtype: DCOSStack
        :param settings: A single stack dict (usually read from the stacks.yaml file)
        """
        self.log = logging.getLogger(self.__class__.__name__)
        self.settings = self.format_settings(settings)
        self.admin_url_scheme = 'https://'
        self.auth_header = None
        self.cf = boto3.resource('cloudformation', region_name=self.settings['Region'])
        self.preprocessed = False

    def process_stack(self):
        """Try to create or update the stack"""
        defaults = {
            'TimeoutInMinutes': 240,
            'Capabilities': ['CAPABILITY_IAM'],
            'Tags': [{'Key': 'Author', 'Value': 'aws-dcos-install'}]
        }
        wait = False

        if not self.preprocessed:
            self.preprocess()

        stackdef = defaults.copy()
        stackdef.update(self.settings)
        self.log.info("processing stack {}".format(stackdef['StackName']))


        try:
            self.log.debug("trying to create stack {}".format(stackdef['StackName']))
            stack = self.cf.create_stack(
                StackName=stackdef['StackName'],
                TemplateURL=stackdef['TemplateURL'],
                Parameters=stackdef['Parameters'],
                TimeoutInMinutes=stackdef['TimeoutInMinutes'],
                Capabilities=stackdef['Capabilities'],
                Tags=stackdef['Tags']
            )
            wait = True
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AlreadyExistsException':
                self.log.debug("stack {} already exists".format(stackdef['StackName']))
                try:
                    stack = self.cf.Stack(stackdef['StackName'])
                    self.log.info("stack {} has status {}".format(stack.name, stack.stack_status))
                    if not stack.stack_status.endswith('_IN_PROGRESS'):
                        self.log.debug("trying to update stack {}".format(stackdef['StackName']))
                        stack.update(
                            StackName=stackdef['StackName'],
                            TemplateURL=stackdef['TemplateURL'],
                            Parameters=stackdef['Parameters'],
                            Capabilities=stackdef['Capabilities'],
                            Tags=stackdef['Tags']
                        )
                        wait = True
                    else:
                        self.log.info("stack {} is busy ({}) - waiting".format(stack.name, stack.stack_status))
                        wait = True
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ValidationError':
                        self.log.info("nothing to update for stack {}".format(stack.name))
                    else:
                        self.log.warning(e)
            else:
                self.log.warning(e)

        while wait and stack.stack_status.endswith('_IN_PROGRESS'):
            time.sleep(5)
            stack = self.cf.Stack(stack.name)
            self.log.info("stack {} has status {}".format(stack.name, stack.stack_status))

    def format_settings(self, settings):
        """Turn the settings input format into something the boto3 CF API understands

        :rtype: dict
        :param settings: Dict of the stack settings
        :return: Dict with stack settings resolved for boto3 processing
        """
        self.log.debug("parsing settings")
        np = []
        for k, v in settings['Parameters'].items():
            self.log.debug("processing k, v {}, {}".format(k, v))
            np.append({'ParameterKey': k, 'ParameterValue': str(v)})
        settings['Parameters'] = np
        return settings

    def preprocess(self):
        """Iterate over the stack ParameterValues and try to resolve any placeholders

        """
        for p in self.settings['Parameters']:
            self.log.debug("found parameter {} with value {}".format(p['ParameterKey'], p['ParameterValue']))
            if p['ParameterValue'].startswith('@') and p['ParameterValue'].endswith('@'):
                self.log.debug("trying to process {}".format(p['ParameterKey']))
                p['ParameterValue'] = self.resolve(p['ParameterValue'])
                self.log.debug("new value of {} is {}".format(p['ParameterKey'], p['ParameterValue']))

        self.preprocessed = True

    def resolve(self, v):
        """Resolves placeholders with their actual value.
        E.g. input @stack.DCOSBaseNetwork.resources.Vpc@ and return vpc-d54e02bc

        :rtype: Union[str, None]
        :param v: ParameterValue of a CloudFormation Stack configuration
        :return: The resolved value
        """
        v = v[1:-1].split('.')  # remove leading and trailing @
        system = v.pop(0)
        if system == 'stack':
            stack_name = v.pop(0)

            action = v.pop(0)
            if action == 'region':
                region_name = v.pop(0)
                action = v.pop(0)
            else:
                region_name = self.settings['Region']

            if action == 'resources':
                logical_id = v.pop(0)
                return self.resources(logical_id, stack_name, region_name)
            elif action == 'outputs':
                key = v.pop(0)
                return self.outputs(stack_name, key, region_name)

        return None

    def outputs(self, stack_name, key, region_name=None):
        """Iterates over the stack outputs and returns the value matching the provided key

        :rtype: Union[str, None]
        :param stack_name: A CloudFormation stack name
        :param key: The OutputKey name e.g. DnsAddress or PublicSlaveDnsAddress
        :param region_name: Name of the AWS Region
        :return: The key value as str or None if the key wasn't found
        """
        if not region_name:
            region_name = self.settings['Region']

        self.log.debug("searching for output value of key {} in stack {} ({})".format(key, stack_name, region_name))
        cf = boto3.resource('cloudformation', region_name=region_name)
        stack = cf.Stack(stack_name)
        if not stack.outputs:
            self.log.debug("stack {} doesn't have any outputs".format(stack_name))
            return None

        for output in stack.outputs:
            self.log.debug("found output {}".format(output))
            if output['OutputKey'] == key:
                self.log.debug("returning match {}".format(output['OutputValue']))
                return output['OutputValue']

        return None

    def resources(self, logical_id, stack_name=None, region_name=None, next_token=None):
        """Return a Stack's Physical Resource ID based of a Logical Resource ID

        :rtype: Union[str, None]
        :param stack_name: A CloudFormation stack name
        :param logical_id: The logical resource ID to search for
        :param next_token: Used internally by the boto3 CF stack resources pagination
        :param region_name: Name of the AWS Region
        :return: The physical resource ID as str or None if the logical resource id wasn't found
        """
        if not stack_name:
            stack_name = self.settings['StackName']
        if not region_name:
            region_name = self.settings['Region']

        self.log.debug("searching for logical resource id {} in stack {} ({})".format(logical_id, stack_name, region_name))
        cfc = boto3.client('cloudformation', region_name=region_name)
        if next_token:
            stack_resources = cfc.list_stack_resources(StackName=stack_name, NextToken=next_token)
        else:
            stack_resources = cfc.list_stack_resources(StackName=stack_name)

        for resource in stack_resources['StackResourceSummaries']:
            self.log.debug("found resource {}".format(resource))
            if resource['LogicalResourceId'] == logical_id:
                self.log.debug("returning match {}".format(resource['PhysicalResourceId']))
                return resource['PhysicalResourceId']

        if 'NextToken' in stack_resources:
            return self.resources(logical_id, stack_name, region_name, stack_resources['NextToken'])

        self.log.warn('did not find resource {}'.format(logical_id))
        return None

    @property
    def admin_addr(self):
        """The Master ELB DNS address

        :rtype: Union[str, None]
        :return: A string of the public agent DNS address
        """
        return self.first_output_value(['DnsAddress', 'MasterDNSName', 'OutputFromNestedStack'])

    @property
    def pubagt_addr(self):
        """The Public Agent DNS address

        :rtype: Union[str, None]
        :return: A string of the public agent DNS address
        """
        return self.first_output_value(['PublicSlaveDnsAddress', 'PublicAgentDNSName'])

    def first_output_value(self, keys):
        """Returns the first value found for a list of stack output keys

        :param keys: A list of output keys
        :return: A string with the first value found
        """
        for key in keys:
            value = self.outputs(self.settings['StackName'], key)
            if value:
                return value

        return None


class DCOSAuth:
    """Used to acquire a DCOS authentication token to make requests to other DCOS components.
    Can also create and delete users and assign them to groups.
    """
    def __init__(self, admin_url, login=None, password=None, description=None):
        """Constructor

        :rtype: DCOSAuth
        :param admin_url: The DCOS UI url
        :param login:
        :param password:
        :param description:
        """
        self.admin_url = admin_url
        self.login = login
        self.password = password
        self.description = description
        self.default_headers = {'Accept': 'application/json', 'Accept-Charset': 'utf-8'}
        self.default_login = {'login': 'bootstrapuser', 'password': 'deleteme'}
        self.auth_header = None
        self.log = logging.getLogger(self.__class__.__name__)

    @property
    def default_login_works(self):
        """Tests if the default login works.

        :rtype: bool
        :return: True or False
        """
        return True if self.default_login_auth_header else False

    @property
    def default_login_auth_header(self):
        """Requests a DCOS authentication token header using default credentials

        :rtype: Union[dict, None]
        :return: authentication header dict or None
        """
        return self.get_auth_header(self.default_login['login'], self.default_login['password'])

    def create_user(self, login, password, description):
        """Create a user

        :rtype: bool
        :param login: The user's login
        :param password: The user's password
        :param description: The user's full name
        :return: True on success
        """
        return self.request('put',
                            '/users/{}'.format(login),
                            json={'password': password,
                                  'description': description
                                  },
                            msg='creating user {}'.format(login)
                            )

    def delete_user(self, login):
        """Delete a user

        :rtype: bool
        :param login: The user's login
        :return: True on success
        """
        return self.request('delete',
                            '/users/{}'.format(login),
                            msg='deleting user {}'.format(login)
                            )

    def add_user_to_group(self, login, group):
        """Add a user to a group

        :rtype: bool
        :param login: The user's login
        :param group: The group to add the user to
        :return: True on success
        """
        return self.request('put',
                            '/groups/{}/users/{}'.format(group, login),
                            msg='adding user {} to group {}'.format(login, group)
                            )

    def request(self, method, path, msg=None, json=None, retfmt='bool', errorfatal=True, autoauth=True, verify_ssl=False):
        """Send a http request to the DCOS authentication service

        :rtype: Union[bool, object, dict, None]
        :param method: HTTP method to use (get, post, put, delete)
        :param path: The API path to send the request to
        :param msg: An optional log message
        :param json: Optional JSON data to be transmitted with the request
        :param verify_ssl: Bool verify SSL certificate when using https admin_url
        :param retfmt: Return format (default=bool, json, request)
                       json will return the r.json() data
                       request will return the entire r object
        :param errorfatal: If True throw exception on error
        :param autoauth: Try to automatically acquire an auth token
        :return: depends on retfmt
        """
        url = self.admin_url + '/acs/api/v1' + path

        if msg:
            self.log.info(msg)

        headers = self.default_headers.copy()

        if not self.auth_header and autoauth:
            self.set_auth_header()

        if self.auth_header:
            headers.update(self.auth_header)

        if method == 'get':
            r = requests.get(url, headers=headers, json=json, verify=verify_ssl)
        elif method == 'post':
            r = requests.post(url, headers=headers, json=json, verify=verify_ssl)
        elif method == 'put':
            r = requests.put(url, headers=headers, json=json, verify=verify_ssl)
        elif method == 'delete':
            r = requests.delete(url, headers=headers, json=json, verify=verify_ssl)

        if 200 <= r.status_code < 300:
            self.log.debug("success")
            if retfmt == 'json':
                self.log.debug('returning json')
                return r.json()
            elif retfmt == 'request':
                self.log.debug('returning request object')
                return r
            else:
                return True
        else:
            if 'Content-Type' in r.headers and r.headers['Content-Type'] == 'application/json':
                resp = r.json()['code']
            else:
                resp = r.reason
            msg = "failed: {}".format(resp)
            self.log.debug(msg)
            if errorfatal:
                raise Exception(msg)
            else:
                if retfmt == 'request':
                    self.log.debug('returning request object')
                    return r
                else:
                    return None

    def get_auth_header(self, login, password):
        """Try to acquire a DCOS authentication token

        :rtype: Union[dict, None]
        :param login: Login to use
        :param password: Password to use
        :return: A header dict with the token or None
        """
        json = self.request('post',
                            '/auth/login',
                            json={'uid': login, 'password': password},
                            msg='authenticating at {} with user {}'.format(self.admin_url, login),
                            errorfatal=False,
                            retfmt='json',
                            autoauth=False
                            )
        if json:
            return {'Authorization': 'token=%s' % json['token']}
        else:
            return None

    def set_auth_header(self):
        """Set the objects authentication header by requesting an auth token

        :rtype: bool
        :return: True or False
        """
        self.auth_header = self.get_auth_header(self.login, self.password)
        return True if self.auth_header else False

    def check_login(self):
        """Test if the configured admin account can authenticate.

        If not create it. Also test if the default bootstrap user exists and if so delete it.
        """
        admin_exists = self.set_auth_header()

        if self.default_login_works:
            self.log.info("default login worked, removing it")
            if admin_exists:
                self.log.info("admin user exists, only deleting default user")
            else:
                # Since the admin user doesn't exist but we were able to authenticate
                # using the default login request an authentication token and
                # explicitly set the object's auth_header to it.
                self.auth_header = self.default_login_auth_header

                self.log.info("admin user doesn't exist, creating it before deleting default user")
                self.create_user(self.login, self.password, self.description)
                self.add_user_to_group(self.login, 'superusers')

            self.delete_user(self.default_login['login'])
        else:
            if not admin_exists:
                self.log.info("default user doesn't exist but admin user doesn't work either - manual intervention required")
            else:
                self.log.info("default user doesn't exist and admin user works - everything looking good")

# add default user back for testing purposes
#        self.log.debug("WARNING: ADDING DEFAULT USER BACK FOR DEVELOPMENT")
#        self.create_user(self.default_login['login'], self.default_login['password'], 'Super User')
#        self.add_user_to_group(self.default_login['login'], 'superusers')

main()
