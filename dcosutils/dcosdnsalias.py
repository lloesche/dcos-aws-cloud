import logging
import boto3


class DCOSDNSAlias:
    """Create a DNS CNAME"""
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.r53 = boto3.client('route53')
        self.hosted_zones = []
        # This blacklist has some hard coded hostnames that should never be
        # updated even if they are defined as aliases in the clusters YAML
        self.blacklist = ['mesosphere.com',
                          'mesosphere.io',
                          'downloads.mesosphere.io',
                          'repos.mesosphere.com',
                          'docs.mesosphere.com',
                          'open.mesosphere.com',
                          'dcos.io',
                          'auth.dcos.io'
                          ]

    def create(self, hostnames, target=None, elb_id=None, elb_region=None, force_alias=False):
        """Create a DNS alias (CNAME or Alias)

        :rtype: None
        :param hostnames: list or string of the DNS alias to create
        :param target: DNS name the hostname(s) should point to - ignored if elb_id and elb_region is provided
        :param elb_id: ID of an ELB we create an ALIAS to
        :param elb_region: Region of the ELB
        :param force_alias: Force creation of an ALIAS instead of a CNAME
        """

        dst_zone_id = None
        if elb_id and elb_region:
            e = boto3.client('elb', region_name=elb_region)
            r = e.describe_load_balancers(LoadBalancerNames=[elb_id])
            target = r['LoadBalancerDescriptions'][0]['CanonicalHostedZoneName']
            dst_zone_id = r['LoadBalancerDescriptions'][0]['CanonicalHostedZoneNameID']
            self.log.debug(
                'found zone: {}, target: {} for ELB with ID {} in region {}'.format(dst_zone_id, target, elb_id,
                                                                                    elb_region))
        else:
            if not target:
                self.log.error('requires either target or elb_id and elb_region')
                return False

        if not isinstance(hostnames, list):
            hostnames = [hostnames]

        for hostname in hostnames:
            if dst_zone_id:
                self.create_alias(hostname, target, dst_zone_id)
            else:
                if force_alias:
                    self.create_alias(hostname, target)
                else:
                    self.create_cname(hostname, target)

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

    def create_alias(self, hostname, target, dst_zone_id=None):
        """Create an ALIAS

        :rtype: bool
        :param hostname: Hostname to create an ALIAS for
        :param target: Destination hostname the ALIAS should point to
        :param dst_zone_id: The zone ID of the destination hostname
        :return:
        """
        self.log.info('creating ALIAS from {} to {}'.format(hostname, target))
        if hostname in self.blacklist:
            self.log.warn('hostname {} is blacklisted'.format(hostname))
            return False

        src_zone_id = self.zone_id(hostname)
        if not dst_zone_id:
            dst_zone_id = self.zone_id(target)
        if not src_zone_id or not dst_zone_id:
            self.log.warn("hostname {} or {} are not in a R53 hosted zone".format(hostname, target))
            return False

        # ALIAS records work different than CNAMEs. Instead of just updating any existing record
        # we first have to DELETE it using the exact same resource record set that is currently
        # configured. We then can CREATE it within the same batch operation.
        complete = False
        next_record_name = None
        next_record_type = None
        delete_rrs = None
        # Search the source zone for any existing resource record that matches the hostname
        # we'd like to create an ALIAS for.
        while not complete:
            if next_record_name and next_record_type:
                r = self.r53.list_resource_record_sets(HostedZoneId=src_zone_id, StartRecordName=next_record_name,
                                                       StartRecordType=next_record_type)
            else:
                r = self.r53.list_resource_record_sets(HostedZoneId=src_zone_id, StartRecordName=hostname+'.')

            for rrs in r['ResourceRecordSets']:
                if rrs['Name'] == hostname+'.':
                    delete_rrs = rrs
                    break

            if r['IsTruncated']:
                next_record_name = r['NextRecordName']
                next_record_type = r['NextRecordType']
            else:
                complete = True

        changes = []
        if delete_rrs:
            self.log.debug('deleting {} before creating ALIAS'.format(delete_rrs['Name']))
            changes.append({
                        'Action': 'DELETE',
                        'ResourceRecordSet': delete_rrs
                    })

        changes.append({
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': hostname,
                            'Type': 'A',
                            "AliasTarget": {
                                "HostedZoneId": dst_zone_id,
                                "DNSName": target,
                                "EvaluateTargetHealth": False
                            }
                        }
                    })

        r = self.r53.change_resource_record_sets(
            HostedZoneId=src_zone_id,
            ChangeBatch={
                'Changes': changes
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

        # If the target hostname is an ELB we use a static zone id mapping
        if not hostname.endswith('elb.amazonaws.com.'):
            for z in self.zones:
                if fuzzy:
                    if hostname.endswith(z['Name']):
                        self.log.debug('zone {} with id {} is a match for {}'.format(z['Name'], z['Id'], hostname))
                        return z['Id'][12:]
                else:
                    if hostname == z['Name']:
                        self.log.debug('zone {} with id {} is a match for {}'.format(z['Name'], z['Id'], hostname))
                        return z['Id'][12:]
        else:
            # This is just a fallback if no ELB ID was provided
            elb_hosted_zone_mapping = {
                "ap-northeast-1": "Z2YN17T5R711GT",
                "ap-southeast-1": "Z1WI8VXHPB1R38",
                "ap-southeast-2": "Z2999QAZ9SRTIC",
                "eu-west-1": "Z3NF1Z3NOM5OY2",
                "eu-central-1": "Z215JYRZR1TBD5",
                "sa-east-1": "Z2ES78Y61JGQKS",
                "us-east-1": "Z3DZXE0Q79N41H",
                "us-west-1": "Z1M58G0W56PQJA",
                "us-west-2": "Z33MTJ483KN6FU",
            }
            region = hostname.split('.')[-5]
            if region in elb_hosted_zone_mapping:
                return elb_hosted_zone_mapping[region]

        self.log.debug('no matching zone found for {}'.format(hostname))
