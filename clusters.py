#!/usr/bin/env python3
import sys
import logging
import yaml
from dcosutils.dcosauth import DCOSAuth
from dcosutils.dcosawsstack import DCOSAWSStack
from dcosutils.dcosdnsalias import DCOSDNSAlias


log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('DCOSAWSStack').setLevel(log_level)
logging.getLogger('DCOSAuth').setLevel(log_level)
logging.getLogger('DCOSDNSAlias').setLevel(log_level)
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

    admin_addr = None
    pubagt_addr = None
    dns_alias = DCOSDNSAlias()

    for cluster in clusters:
        for stack in cluster['Stacks']:
            dcos_stack = DCOSAWSStack(stack)
            dcos_stack.process_stack()

            if not admin_addr:
                admin_addr = dcos_stack.admin_addr
            if not pubagt_addr:
                pubagt_addr = dcos_stack.pubagt_addr

        if admin_addr:
            dcos_auth = DCOSAuth('https://' + admin_addr, cluster['Admin'], cluster['AdminPassword'], 'Admin')
            dcos_auth.check_login()

        if cluster['DNS']:
            log.debug("creating DNS aliases")
            if admin_addr and cluster['DNS']['MasterAlias']:
                dns_alias.create(cluster['DNS']['MasterAlias'], admin_addr)
            if pubagt_addr and cluster['DNS']['PubAgentAlias']:
                dns_alias.create(cluster['DNS']['PubAgentAlias'], pubagt_addr)


if __name__ == "__main__":
    main(sys.argv[1:])
