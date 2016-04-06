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
    config = yaml.load(open('ebs-backup.yaml').read())
    ebs_backup = EBSBackup(config)
    ebs_backup.backup()

if __name__ == "__main__":
    main(sys.argv[1:])
