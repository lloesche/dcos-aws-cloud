import logging
import boto3


class DCOSAWSSecurityGroup:
    """Represents an AWS DCOS Security Group"""
    def __init__(self, sg_id, region):
        """Constructor

        :rtype: DCOSAWSSecurityGroup
        :param sg_id: AWS Security Group ID
        :param region: AWS Region Name
        """
        ec2 = boto3.resource('ec2', region_name=region)
        self.log = logging.getLogger(self.__class__.__name__)
        self.sg = ec2.SecurityGroup(sg_id)

    def allow(self, sources, ports, protocol='tcp', source_type='cidr'):
        """Allow a list of ports for a list of IPs

        :param sources: A list of IPs
        :param ports: A list of Ports
        :param protocol: The IP protocol to allow
        :param source_type: Type of sources, either 'cidr' or 'group'
        """
        new_ip_permissions = []

        type_key = 'IpRanges'
        source_key = 'CidrIp'

        if source_type == 'group':
            type_key = 'UserIdGroupPairs'
            source_key = 'GroupId'

        for source in sources:
            for port in ports:
                if self.policy_exists(source, port, type_key, source_key, protocol):
                    self.log.debug("found existing policy to ALLOW {}:{} ({})".format(source, port, protocol))
                else:
                    self.log.debug("adding new policy to ALLOW {}:{} ({})".format(source, port, protocol))
                    new_ip_permissions.append(
                        {
                            'IpProtocol': protocol,
                            'FromPort': port,
                            'ToPort': port,
                            type_key: [{source_key: source}]
                        }
                    )

        if len(new_ip_permissions) > 0:
            self.log.debug("committing ingress policy")
            self.sg.authorize_ingress(IpPermissions=new_ip_permissions)
        else:
            self.log.debug("no policy changes required")

    def policy_exists(self, source, port, type_key, source_key, protocol='tcp'):
        """Check if a security policy already exists

        :rtype: bool
        :param source: Source from where access is performed (either CIDR or Security Group string)
        :param port: IP port number
        :param type_key: Name of the Type of IP Permission (IpRanges or UserIdGroupPairs)
        :param source_key: Name of the Source of IP Permission (CidrIp or GroupId)
        :param protocol: IP protocol (tcp, udp, icmp)
        :return: boolean
        """
        for permission in self.sg.ip_permissions:
            for existing_source in permission[type_key]:
                existing_source = existing_source[source_key]
                if permission['FromPort'] == port and permission['ToPort'] == port and permission['IpProtocol'] == protocol and existing_source == source:
                    return True
        return False
