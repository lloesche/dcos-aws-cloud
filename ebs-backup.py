#!/usr/bin/env python3
import sys
import yaml
import logging
from dcosutils.ebsbackup import EBSBackup

log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('EBSBackup').setLevel(log_level)


def main(argv):
    backup_file = argv[0] if len(argv) > 0 else 'ebs-backup.yaml'
    config = yaml.load(open(backup_file).read())
    ebs_backup = EBSBackup(config)
    ebs_backup.backup()

if __name__ == "__main__":
    main(sys.argv[1:])
