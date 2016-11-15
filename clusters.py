#!/usr/bin/env python3
import sys
import logging
import yaml
import argparse
from dcosutils.dcosauth import DCOSAuth
from dcosutils.dcosawsstack import DCOSAWSStack
from dcosutils.dcosawssg import DCOSAWSSecurityGroup
from dcosutils.dcosdnsalias import DCOSDNSAlias


log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('DCOSAWSStack').setLevel(log_level)
logging.getLogger('DCOSAuth').setLevel(log_level)
logging.getLogger('DCOSDNSAlias').setLevel(log_level)
logging.getLogger('DCOSAWSSecurityGroup').setLevel(log_level)
log = logging.getLogger(__name__)


def main(argv):
    """Entry point

    Loads the file clusters.yaml and processes all the defined cluster stacks.
    Processing means it either creates or updates the stack to match it's specification.
    After that it checks that the default bootstrap user no longer exists and that the
    admin user has been created.
    """
    p = argparse.ArgumentParser(description='Install DC/OS on AWS Cloud')
    p.add_argument('--clusters', help='YAML File with the Clusters definition (default: clusters.yaml)',
                   dest='clusters_file', default='clusters.yaml')
    p.add_argument('--no-r53', help="Don't attempt to update AWS R53", dest='route53', action='store_false',
                   default=True)
    p.add_argument('--ee', help="Assume Installation of Enterprise DC/OS", dest='enterprise',
                   action='store_true', default=False)
    args = p.parse_args(argv)

    log.debug("reading {}".format(args.clusters_file))
    clusters = yaml.load(open(args.clusters_file).read())

    dns_alias = DCOSDNSAlias()

    for cluster in clusters:
        admin_addr = None   # Hostname of the Adminrouter ELB
        admin_sg = None     # Admin Security Group
        pubagt_addr = None  # Public Agent ELB

        for stack in cluster['Stacks']:
            # Regions are processed per Stack but for user convenience
            # we allow copying the Region from the overall Cluster
            # definition if it's not defined on the Stack level
            if 'Region' not in stack and 'Region' in cluster:
                stack['Region'] = cluster['Region']
            dcos_stack = DCOSAWSStack(stack)
            dcos_stack.process_stack()

            # Depending on which Cloudformation Template is being used
            # (simple, zen or advanced) the following three Strings
            # might appear in different Stacks
            if not admin_addr:
                admin_addr = dcos_stack.admin_addr
            if not admin_sg:
                admin_sg = dcos_stack.admin_sg
            if not pubagt_addr:
                pubagt_addr = dcos_stack.pubagt_addr

        # Ensure that all admin locations are part of the security group.
        # The Cloudformation template only allows a single network/IP to be allowed for access.
        # This will add additional source IPs/networks to the admin security group.
        if admin_sg and 'AdminLocations' in cluster:
            log.debug("permitting admin locations in {} ({})".format(admin_sg['id'], admin_sg['region']))
            dcos_sg = DCOSAWSSecurityGroup(admin_sg['id'], admin_sg['region'])
            dcos_sg.allow(cluster['AdminLocations'], [22, 80, 443], source_type='cidr')
            # dcos_sg.allow([admin_sg['id']], [443], source_type='group')

        # On Enterprise DC/OS remove the default user and add the configured admin login
        if admin_addr and args.enterprise and 'Admin' in cluster and 'AdminPassword' in cluster:
            dcos_auth = DCOSAuth('http://' + admin_addr, cluster['Admin'], cluster['AdminPassword'], 'Admin')
            dcos_auth.check_login()

        # Create/update DNS aliases
        if 'DNS' in cluster and args.route53:
            log.debug("creating DNS aliases")
            if admin_addr and 'MasterAlias' in cluster['DNS']:
                dns_alias.create(cluster['DNS']['MasterAlias'], admin_addr)
            if pubagt_addr and 'PubAgentAlias' in cluster['DNS']:
                dns_alias.create(cluster['DNS']['PubAgentAlias'], pubagt_addr)

        # Output login URL
        if admin_addr:
            log.info("Log in at http://{}".format(admin_addr))
            if 'DNS' in cluster and args.route53 and 'MasterAlias' in cluster['DNS']:
                log.info("or at http://{} if previous R53 operation was successful".format(cluster['DNS']['MasterAlias'][0]))


if __name__ == "__main__":
    main(sys.argv[1:])
