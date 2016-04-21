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

    def allow(self, ip_ranges, ports, protocol='tcp'):
        """Allow a list of ports for a list of IPs

        :param ip_ranges: A list of IPs
        :param ports: A list of Ports
        :param protocol: The IP protocol to allow
        """
        new_ip_permissions = []

        for location in ip_ranges:
            for port in ports:
                if self.policy_exists(location, port):
                    self.log.debug("found existing policy to ALLOW {}:{}".format(location, port))
                else:
                    self.log.debug("adding new policy to ALLOW {}:{}".format(location, port))
                    new_ip_permissions.append(
                        {
                            'IpProtocol': protocol,
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [{'CidrIp': location}]
                        }
                    )

        if len(new_ip_permissions) > 0:
            self.log.debug("committing ingress policy")
            self.sg.authorize_ingress(IpPermissions=new_ip_permissions)
        else:
            self.log.debug("no policy changes required")

    def policy_exists(self, location, port):
        for permission in self.sg.ip_permissions:
            for cidr_ip in permission['IpRanges']:
                cidr_ip = cidr_ip['CidrIp']
                if permission['FromPort'] == port and permission['ToPort'] == port and cidr_ip == location:
                    return True
        return False
