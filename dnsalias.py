#!/usr/bin/env python3
import sys
import logging
import argparse
from dcosutils.dcosdnsalias import DCOSDNSAlias

log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('DCOSDNSAlias').setLevel(log_level)
log = logging.getLogger(__name__)


def main(argv):
    """Entry point

    """
    dns = DCOSDNSAlias()
    p = argparse.ArgumentParser(description='Create a R53 CNAME or ALIAS')
    p.add_argument('--source', '-s', help='Source', dest='src', required=True)
    p.add_argument('--destination', '-d', help='Destination', dest='dst', required=False, default=None)
    p.add_argument('--elb-id', '-e', help='ELB ID', dest='elb_id', required=False, default=None)
    p.add_argument('--elb-region', '-r', help='ELB Region', dest='elb_region', required=False, default=None)
    p.add_argument('--force-alias', '-f', help='Force creation of an ALIAS instead of a CNAME', dest='force_alias',
                   required=False, action='store_false', default=False)
    args = p.parse_args(argv)

    dns.create(args.src, target=args.dst, elb_id=args.elb_id, elb_region=args.elb_region, force_alias=args.force_alias)


if __name__ == "__main__":
    main(sys.argv[1:])
