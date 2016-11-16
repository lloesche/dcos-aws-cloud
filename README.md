# dcos-aws-cloud
AWS installer scripts for DC/OS

Script to automatically deploy, update and backup our AWS DC/OS production cluster(s).

## Getting Started

### DCOS AWS Clusters
clusters.py will read the config file given as arg or clusters.yaml by default.
All clusters defined in that file will be created or if existing clusters have changed updated.
Note however that removed clusters won't be deleted on AWS.

The config file is YAML formatted and contains the following structure:
```

---
- ClusterName: A Name for the Cluster
  Admin: The-Admin-Login-Name
  AdminPassword: The-Admin-Password
  DNS:
    MasterAlias:
    - some.hostname
    PubAgentAlias:
    - some.other.hostname
  Stacks:
  - StackName: somestackname
    Region: us-west-1
    TemplateURL: http://...
    Parameters:
      somekey: somevalue
```

The file can define any number of clusters and every cluster can consist of any number of stacks.
Stacks can reference each others outputs or resources in the Parameter values.

To do so use the following Syntax:

@stack._StackName_.resources._ResourceName_@

@stack._StackName_.outputs._ResourceName_@

If the stack was created in a different region an optional region argument can be given.

@stack._StackName_.region._AWSRegion_.resources._ResourceName_@

#### Example configuration
```

---
- ClusterName: dcos
  Admin: admin
  AdminPassword: pC7VknRGGr7jAM
  DNS:
    MasterAlias:
      - dcos.test.mesosphere.com
    PubAgentAlias:
      - servicea.test.mesosphere.com
      - serviceb.test.mesosphere.com
  Stacks:
  - StackName: DCOSInfra
    Region: eu-central-1
    TemplateURL: https://s3.amazonaws.com/downloads.mesosphere.io/dcos/testing/continuous/cloudformation/infra.json
    Parameters:
      AdminLocation: '0.0.0.0/0'
      InternetGateway: '@stack.DCOSBaseNetwork.resources.InternetGateway@'
      KeyName: 'default'
      PrivateSubnet: '@stack.DCOSBaseNetwork.resources.PrivateSubnet@'
      PublicSubnet: '@stack.DCOSBaseNetwork.resources.PublicSubnet@'
      Vpc: '@stack.DCOSBaseNetwork.resources.Vpc@'
  - StackName: DCOSMaster
    Region: eu-central-1
    TemplateURL: https://s3.amazonaws.com/downloads.mesosphere.io/dcos/testing/continuous/cloudformation/ee.advanced-master-5.json
    Parameters:
      AcceptEULA: 'Yes'
      AdminSecurityGroup: '@stack.DCOSInfra.resources.AdminSecurityGroup@'
      ExhibitorS3Bucket: '@stack.DCOSInfra.resources.ExhibitorS3Bucket@'
      KeyName: 'default'
      LbSecurityGroup: '@stack.DCOSInfra.resources.LbSecurityGroup@'
      MasterInstanceType: 'm3.xlarge'
      MasterSecurityGroup: '@stack.DCOSInfra.resources.MasterSecurityGroup@'
      PrivateAgentSecurityGroup: '@stack.DCOSInfra.resources.PrivateAgentSecurityGroup@'
      PrivateSubnet: '@stack.DCOSBaseNetwork.resources.PrivateSubnet@'
      PublicAgentSecurityGroup: '@stack.DCOSInfra.resources.PublicAgentSecurityGroup@'
      PublicSubnet: '@stack.DCOSBaseNetwork.resources.PublicSubnet@'
  - StackName: DCOSPrivAgent
    Region: eu-central-1
    TemplateURL: https://s3.amazonaws.com/downloads.mesosphere.io/dcos/testing/continuous/cloudformation/ee.advanced-priv-agent.json
    Parameters:
      InternalMasterLoadBalancerDnsName: '@stack.DCOSMaster.outputs.InternalMasterLoadBalancerDnsName@'
      KeyName: 'default'
      PrivateAgentInstanceCount: 5
      PrivateAgentInstanceType: 'm3.xlarge'
      PrivateAgentSecurityGroup: '@stack.DCOSInfra.resources.PrivateAgentSecurityGroup@'
      PrivateSubnet: '@stack.DCOSBaseNetwork.resources.PrivateSubnet@'
  - StackName: DCOSPubAgent
    Region: eu-central-1
    TemplateURL: https://s3.amazonaws.com/downloads.mesosphere.io/dcos/testing/continuous/cloudformation/ee.advanced-pub-agent.json
    Parameters:
      InternalMasterLoadBalancerDnsName: '@stack.DCOSMaster.outputs.InternalMasterLoadBalancerDnsName@'
      KeyName: 'default'
      PublicAgentInstanceCount: 2
      PublicAgentInstanceType: 'm3.xlarge'
      PublicAgentSecurityGroup: '@stack.DCOSInfra.resources.PublicAgentSecurityGroup@'
      PublicSubnet: '@stack.DCOSBaseNetwork.resources.PublicSubnet@'
```

### EBS Backups
ebs-backup.py  will read the config file given as arg or ebs-backup.yaml by default.

The config file is YAML formatted and contains the following structure:
```

---
- Region: eu-central-1
  Retention: 7 days
  Volumes: all
- Region: us-west-2
  Retention: 7 days
  Volumes:
    - vol-43834afa
```

You can either provide a list of volumes to backup in each region or tell it to backup all volumes.
