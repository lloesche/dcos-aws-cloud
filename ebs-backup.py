#!/usr/bin/env python3
import sys
import yaml
from dcosutils.ebsbackup import EBSBackup


def main(argv):
    config = yaml.load(open('ebs-backup.yaml').read())
    ebs_backup = EBSBackup(config)
    ebs_backup.backup()

if __name__ == "__main__":
    main(sys.argv[1:])
