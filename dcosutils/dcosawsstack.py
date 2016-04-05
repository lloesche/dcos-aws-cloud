import logging
import time
import boto3
import botocore.exceptions


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
