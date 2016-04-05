import logging
import boto3

class DCOSDNSAlias:
    """Create a DNS CNAME"""
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.r53 = boto3.client('route53')
        self.hosted_zones = []
        self.blacklist = ['mesosphere.com',
                          'mesosphere.io',
                          'downloads.mesosphere.io',
                          'repos.mesosphere.com',
                          'docs.mesosphere.com',
                          'open.mesosphere.com'
                          ]

    def create(self, hostnames, target):
        """Create a DNS alias (CNAME or Alias)

        :rtype: None
        :param hostnames: list or string of the DNS alias to create
        :param target: DNS name the hostname(s) should point to
        """
        if isinstance(hostnames, list):
            for hostname in hostnames:
                self.create_cname(hostname, target)
        else:
            self.create_cname(hostnames, target)

    def create_cname(self, hostname, target):
        """Create a CNAME

        :rtype: bool
        :param hostname: Hostname to create a CNAME for
        :param target: String the CNAME should point to
        :return:
        """
        self.log.info('creating CNAME from {} to {}'.format(hostname, target))
        if hostname in self.blacklist:
            self.log.warn('hostname {} is blacklisted'.format(hostname))
            return False

        src_zone_id = self.zone_id(hostname)
        if not src_zone_id:
            self.log.warn("hostname {} is not in a R53 hosted zone".format(hostname))
            return False

        r = self.r53.change_resource_record_sets(
            HostedZoneId=src_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': hostname,
                            'Type': 'CNAME',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': target
                                }
                            ]
                        }
                    }
                ]
            })
        if r:
            self.log.debug("submitted change request with ID {} status is {}".format(r['ChangeInfo']['Id'], r['ChangeInfo']['Status']))
            return True
        else:
            return False

    @property
    def zones(self):
        """Return the list of R53 hosted zones

        :rtype: list
        :return: List of zones
        """
        if len(self.hosted_zones) < 1:
            self.fetch_zones()
        return self.hosted_zones

    def fetch_zones(self):
        """Fetch the list of R53 hosted zones

        :rtype: None
        """
        self.log.debug('refreshing list of zones')
        complete = False
        next_marker = None
        zones = []

        while not complete:
            if next_marker:
                hz = self.r53.list_hosted_zones(Marker=next_marker)
            else:
                hz = self.r53.list_hosted_zones()

            zones.extend(hz['HostedZones'])

            if hz['IsTruncated']:
                next_marker = hz['NextMarker']
            else:
                complete = True

        self.hosted_zones = zones  # swap the list

    def zone_id(self, hostname, fuzzy=True):
        """Returns the R53 zone id of a given hostname

        :rtype: Union[str, None]
        :param hostname: DNS name for which to find the R53 zone ID
        :param fuzzy: bool whether to match the exact hostname or just the end of it
        :return:
        """
        self.log.debug('searching for zone ID of {}'.format(hostname))
        if not hostname.endswith('.'):
            hostname += '.'
        for z in self.zones:
            if fuzzy:
                if hostname.endswith(z['Name']):
                    self.log.debug('zone {} with id {} is a match for {}'.format(z['Name'], z['Id'], hostname))
                    return z['Id']
            else:
                if hostname == z['Name']:
                    self.log.debug('zone {} with id {} is a match for {}'.format(z['Name'], z['Id'], hostname))
                    return z['Id']
        self.log.debug('no matching zone found for {}'.format(hostname))
