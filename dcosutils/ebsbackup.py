import boto3
import parsedatetime
import datetime


class EBSBackup:
    def __init__(self, config):
        self.config = config
        self._cal = parsedatetime.Calendar()

    def backup(self):
        """Backup volumes specified in config and clean up old snapshots"""
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
        """Create EBS Snapshot of a volume and tag it

        :param volume: A boto3.Volume
        """
        description = '{}-backup-{}'.format(volume.volume_id, datetime.date.today())
        log.info('backing up volume {}'.format(volume.volume_id))
        snapshot = volume.create_snapshot(
            Description=description
        )
        snapshot.create_tags(
            Tags=[{'Key': 'author', 'Value': 'backup'}]
        )

    def _cleanup_snapshots(self, volume, retention):
        """Clean up snapshots older than the configured retention time

        :param volume: A boto3.Volume
        :param retention: A string specifying how old snapshots are allowed to be
        """
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

            expire_at = self._cal.parseDT(retention, snapshot.start_time)[0]
            log.debug('snapshot {} was created at {} and is set to expire at {}'.format(snapshot.snapshot_id, snapshot.start_time, expire_at))
            if expire_at > datetime.datetime.utcnow():
                log.debug('snapshot {} is not yet expired'.format(snapshot.snapshot_id))
                continue

            log.debug('snapshot {} is expired - removing it'.format(snapshot.snapshot_id))
            snapshot.delete()

