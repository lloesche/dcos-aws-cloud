#!/usr/bin/env python3
import boto3
import yaml
import botocore.exceptions
import logging
import parsedatetime
import datetime

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(logging.DEBUG)
log = logging.getLogger(__name__)
cal = parsedatetime.Calendar()

config = yaml.load(open('ebs-backup.yaml').read())


def main():
    ebs_backup = EBSBackup(config)
    ebs_backup.backup()


class EBSBackup:
    def __init__(self, config):
        self.config = config

    def backup(self):
        for region_config in self.config:
            region_name = region_config['Region']
            ec2 = boto3.resource('ec2', region_name=region_name)
            retention = region_config['Retention']
            volumes = region_config['Volumes']
            if isinstance(volumes, str):
                if volumes == 'all':
                    log.info('backing up all volumes for region {}'.format(region_name))
                    for volume in ec2.volumes.all():
                        self._snapshot_volume(volume)
                        self._cleanup_snapshots(volume, retention)
            else:
                for volume_id in volumes:
                    volume = ec2.Volume(volume_id)
                    self._snapshot_volume(volume)
                    self._cleanup_snapshots(volume, retention)

    def _snapshot_volume(self, volume):
        description = '{}-backup-{}'.format(volume.volume_id, datetime.date.today())
        log.info('backing up volume {}'.format(volume.volume_id))
        snapshot = volume.create_snapshot(
            Description=description
        )
        snapshot.create_tags(
            Tags=[{'Key': 'author', 'Value': 'backup'}]
        )

    def _cleanup_snapshots(self, volume, retention):
        log.info('cleaning up snapshots of volume {}'.format(volume.volume_id))
        for snapshot in volume.snapshots.all():
            log.info('processing snapshot {}'.format(snapshot.snapshot_id))

            consider_snapshot = False
            tags = snapshot.tags
            if tags:
                for tag in tags:
                    if tag['Key'] == 'author' and tag['Value'] == 'backup':
                        consider_snapshot = True
                        log.debug('snapshot {} was originally created by us - processing it further'.format(snapshot.snapshot_id))
                        break
            if not consider_snapshot:
                log.debug('snapshot {} was not originally created by us - ignoring it'.format(snapshot.snapshot_id))
                continue

            expire_at = cal.parseDT(retention, snapshot.start_time)[0]
            log.debug('snapshot {} was created at {} and is set to expire at {}'.format(snapshot.snapshot_id, snapshot.start_time, expire_at))
            if expire_at > datetime.datetime.utcnow():
                log.debug('snapshot {} is not yet expired'.format(snapshot.snapshot_id))
                continue

            log.debug('snapshot {} is expired - removing it'.format(snapshot.snapshot_id))
            snapshot.delete()

main()
