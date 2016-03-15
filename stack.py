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
    log.debug("reading stacks.yaml")
    stacks = yaml.load(open('stacks.yaml').read())
    for stack in stacks:
        dcos = DCOS(stack)
        dcos.process_stack()
        dcos.check_login()


class DCOS:
    def __init__(self, settings):
        self.settings = settings
        self.log = logging.getLogger(self.__class__.__name__)
        self.adminurl_scheme = 'http://'
        self.auth_header = None
        self.cf = boto3.resource('cloudformation', region_name=self.settings['Region'])

    def process_stack(self):
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

    def outputs(self, name):
        stack = self.cf.Stack(self.settings['StackName'])
        for output in stack.outputs:
            if output['OutputKey'] == name:
                return self.adminurl_scheme + output['OutputValue']

        return None

    @property
    def adminurl(self):
        return self.outputs('DnsAddress')

    @property
    def pubagturl(self):
        return self.outputs('PublicSlaveDnsAddress')

    def check_login(self):
        # request with json in the body
        # Content-Type: application/json; charset=utf-8
        #
        # requests expecting non empty body
        # Accept: application/json
        # Accept-Charset: utf-8

        dcos_auth = DCOSAuth(self.adminurl, self.settings['Admin'], self.settings['AdminPassword'], 'Admin')
        admin_exists = dcos_auth.set_auth_header()

        if dcos_auth.test_default_login():
            log.info("default login worked, removing it")
            if admin_exists:
                log.info("admin user exists, only deleting default user")
            else:
                dcos_auth.auth_header = dcos_auth.default_login_auth_header()
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
    def __init__(self, adminurl, login=None, password=None, description=None):
        self.adminurl = adminurl
        self.login = login
        self.password = password
        self.description = description
        self.default_headers = {'Accept': 'application/json', 'Accept-Charset': 'utf-8'}
        self.default_login = {'login': 'bootstrapuser', 'password': 'deleteme'}
        self.auth_header = None

    def test_default_login(self):
        return True if self.default_login_auth_header() else False

    def default_login_auth_header(self):
        return self.get_auth_header(self.default_login['login'], self.default_login['password'])

    def create_user(self, login, password, description):
        return self.request('put',
                            '/acs/api/v1/users/{}'.format(login),
                            json={'password': password,
                                  'description': description
                                  },
                            msg='creating user {}'.format(login)
                            )

    def delete_user(self, login):
        return self.request('delete',
                            '/acs/api/v1/users/{}'.format(login),
                            msg='deleting user {}'.format(login)
                            )

    def add_user_to_group(self, login, group):
        return self.request('put',
                            '/acs/api/v1/groups/{}/users/{}'.format(group, login),
                            msg='adding user {} to group {}'.format(login, group)
                            )

    def request(self, method, path, msg=None, json=None, retfmt='bool', errorfatal=True, autoauth=True):
        url = self.adminurl + path

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
        json = self.request('post',
                            '/acs/api/v1/auth/login',
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
        self.auth_header = self.get_auth_header(self.login, self.password)
        return True if self.auth_header else False

main()
