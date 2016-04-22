#!/usr/bin/env python3
import sys
import logging
import yaml
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

    clusters_file = argv[0] if len(argv) > 0 else 'clusters.yaml'

    log.debug("reading {}".format(clusters_file))
    clusters = yaml.load(open(clusters_file).read())

    dns_alias = DCOSDNSAlias()

    for cluster in clusters:
        admin_addr = None
        admin_sg = None
        pubagt_addr = None
        for stack in cluster['Stacks']:
            dcos_stack = DCOSAWSStack(stack)
            dcos_stack.process_stack()

            if not admin_addr:
                admin_addr = dcos_stack.admin_addr
            if not admin_sg:
                admin_sg = dcos_stack.admin_sg
            if not pubagt_addr:
                pubagt_addr = dcos_stack.pubagt_addr

        # ensure that all admin locations are part of the security group
        if admin_sg and cluster['AdminLocations']:
            log.debug("permitting admin locations in {} ({})".format(admin_sg['id'], admin_sg['region']))
            dcos_sg = DCOSAWSSecurityGroup(admin_sg['id'], admin_sg['region'])
            dcos_sg.allow(cluster['AdminLocations'], [22, 80, 443], source_type='cidr')
            dcos_sg.allow([admin_sg['id']], [443], source_type='group')

        # remove the default user and add the configured admin login
        if admin_addr:
            dcos_auth = DCOSAuth('https://' + admin_addr, cluster['Admin'], cluster['AdminPassword'], 'Admin')
            dcos_auth.check_login()

        # create/update DNS aliases
        if cluster['DNS']:
            log.debug("creating DNS aliases")
            if admin_addr and cluster['DNS']['MasterAlias']:
                dns_alias.create(cluster['DNS']['MasterAlias'], admin_addr)
            if pubagt_addr and cluster['DNS']['PubAgentAlias']:
                dns_alias.create(cluster['DNS']['PubAgentAlias'], pubagt_addr)


if __name__ == "__main__":
    main(sys.argv[1:])
