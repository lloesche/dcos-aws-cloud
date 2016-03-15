#!/usr/bin/env python3
import boto3
import time
import yaml
import requests
import botocore.exceptions
import logging

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('DCOS').setLevel(logging.DEBUG)
logging.getLogger('__main__').setLevel(logging.DEBUG)
#logging.getLogger('requests').setLevel(logging.DEBUG)
log = logging.getLogger(__name__)


def main():
    """Entry point

    Loads the file stacks.yaml and processes all the defined stacks.
    Processing means it either creates or updates the stack to match it's specification.
    After that it checks that the default bootstrap user no longer exists and that the
    admin user has been created.
    """
    log.debug("reading stacks.yaml")
    stacks = yaml.load(open('stacks.yaml').read())
    for stack in stacks:
        dcos = DCOS(stack)
        dcos.process_stack()
        dcos.check_login()


class DCOS:
    """Represents an AWS DCOS stack"""
    def __init__(self, settings):
        """Constructor

        :rtype: DCOS
        :param settings: A single stack dict (usually read from the stacks.yaml file)
        """
        self.settings = settings
        self.log = logging.getLogger(self.__class__.__name__)
        self.adminurl_scheme = 'http://'
        self.auth_header = None
        self.cf = boto3.resource('cloudformation', region_name=self.settings['Region'])

    def process_stack(self):
        """Try to create or update the stack"""
        defaults = {
            'TimeoutInMinutes': 240,
            'Capabilities': ['CAPABILITY_IAM'],
            'Tags': [{'Key': 'author', 'Value': 'autoinstaller'}]
        }
        wait = False
        stackdef = defaults.copy()
        stackdef.update(self.settings)
        log.info("processing stack {}".format(stackdef['StackName']))


        try:
            log.debug("trying to create stack {}".format(stackdef['StackName']))
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
                log.debug("stack {} already exists".format(stackdef['StackName']))
                try:
                    stack = self.cf.Stack(stackdef['StackName'])
                    log.info("stack {} has status {}".format(stack.name, stack.stack_status))
                    if stack.stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                        log.debug("trying to update stack {}".format(stackdef['StackName']))
                        stack.update(
                            StackName=stackdef['StackName'],
                            TemplateURL=stackdef['TemplateURL'],
                            Parameters=stackdef['Parameters'],
                            Capabilities=stackdef['Capabilities'],
                            Tags=stackdef['Tags']
                        )
                        wait = True
                    else:
                        log.info("stack {} is busy ({}) - retry again later".format(stack.name, stack.stack_status))
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ValidationError':
                        log.info("nothing to update for stack {}".format(stack.name))
                    else:
                        log.warning(e)
            else:
                log.warning(e)

        while wait and stack.stack_status not in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
            time.sleep(5)
            stack = self.cf.Stack(stack.name)
            log.info("stack {} has status {}".format(stack.name, stack.stack_status))

    def outputs(self, key):
        """Iterates over the stack outputs and returns the value matching the provided key

        :rtype: Union[str, None]
        :param key: The OutputKey name e.g. DnsAddress or PublicSlaveDnsAddress
        :return: The key value as str or None if the key wasn't found
        """
        stack = self.cf.Stack(self.settings['StackName'])
        for output in stack.outputs:
            if output['OutputKey'] == key:
                return self.adminurl_scheme + output['OutputValue']

        return None

    @property
    def adminurl(self):
        """The Public Agent DNS address

        :rtype: str
        :return: A string of the public agent DNS address
        """
        return self.outputs('DnsAddress')

    @property
    def pubagturl(self):
        """The Public Agent DNS address

        :rtype: str
        :return: A string of the public agent DNS address
        """
        return self.outputs('PublicSlaveDnsAddress')

    def check_login(self):
        """Test if the configured admin account can authenticate.

        If not create it. Also test if the default bootstrap user exists and if so delete it.
        """
        dcos_auth = DCOSAuth(self.adminurl, self.settings['Admin'], self.settings['AdminPassword'], 'Admin')
        admin_exists = dcos_auth.set_auth_header()

        if dcos_auth.default_login_works:
            log.info("default login worked, removing it")
            if admin_exists:
                log.info("admin user exists, only deleting default user")
            else:
                # Since the admin user doesn't exist but we were able to authenticate
                # using the default login request an authentication token and
                # explicitly set the object's auth_header to it.
                dcos_auth.auth_header = dcos_auth.default_login_auth_header

                log.info("admin user doesn't exist, creating it before deleting default user")
                dcos_auth.create_user(self.settings['Admin'], self.settings['AdminPassword'], 'Admin')
                dcos_auth.add_user_to_group(self.settings['Admin'], 'superusers')

            dcos_auth.delete_user(dcos_auth.default_login['login'])
        else:
            if not admin_exists:
                log.info("default user doesn't exist but admin user doesn't work either - manual intervention required")
            else:
                log.info("default user doesn't exist and admin user works - everything looking good")

# add default user back for testing purposes
#        dcos_auth.create_user(dcos_auth.default_login['login'], dcos_auth.default_login['password'], 'Super User')
#        dcos_auth.add_user_to_group(dcos_auth.default_login['login'], 'superusers')


class DCOSAuth:
    """Used to acquire a DCOS authentication token to make requests to other DCOS components.
    Can also create and delete users and assign them to groups.
    """
    def __init__(self, adminurl, login=None, password=None, description=None):
        """Constructor

        :rtype: DCOSAuth
        :param adminurl: The DCOS UI url
        :param login:
        :param password:
        :param description:
        """
        self.adminurl = adminurl
        self.login = login
        self.password = password
        self.description = description
        self.default_headers = {'Accept': 'application/json', 'Accept-Charset': 'utf-8'}
        self.default_login = {'login': 'bootstrapuser', 'password': 'deleteme'}
        self.auth_header = None

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

    def request(self, method, path, msg=None, json=None, retfmt='bool', errorfatal=True, autoauth=True):
        # request with json in the body
        # Content-Type: application/json; charset=utf-8
        #
        # requests expecting non empty body
        # Accept: application/json
        # Accept-Charset: utf-8
        """Send a http request to the DCOS authentication service

        :rtype: Union[bool, object, dict, None]
        :param method: HTTP method to use (get, post, put, delete)
        :param path: The API path to send the request to
        :param msg: An optional log message
        :param json: Optional JSON data to be transmitted with the request
        :param retfmt: Return format (default=bool, json, request)
                       json will return the r.json() data
                       request will return the entire r object
        :param errorfatal: If True throw exception on error
        :param autoauth: Try to automatically acquire an auth token
        :return: depends on retfmt
        """
        url = self.adminurl + '/acs/api/v1' + path

        if msg:
            log.info(msg)

        headers = self.default_headers.copy()

        if not self.auth_header and autoauth:
            self.set_auth_header()

        if self.auth_header:
            headers.update(self.auth_header)

        if method == 'get':
            r = requests.get(url, headers=headers, json=json)
        elif method == 'post':
            r = requests.post(url, headers=headers, json=json)
        elif method == 'put':
            r = requests.put(url, headers=headers, json=json)
        elif method == 'delete':
            r = requests.delete(url, headers=headers, json=json)

        if 200 <= r.status_code < 300:
            log.debug("success")
            if retfmt == 'json':
                log.debug('returning json')
                return r.json()
            elif retfmt == 'request':
                log.debug('returning request object')
                return r
            else:
                return True
        else:
            if r.headers['Content-Type'] and r.headers['Content-Type'] == 'application/json':
                resp = r.json()['code']
            else:
                resp = r.reason
            msg = "failed: {}".format(resp)
            log.debug(msg)
            if errorfatal:
                raise Exception(msg)
            else:
                if retfmt == 'request':
                    log.debug('returning request object')
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
                            msg='authenticating at {} with user {}'.format(self.adminurl, login),
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

main()
