import {
  Fn,
  Stack,
  StackProps,
  aws_iam as iam,
  aws_ec2 as ec2,
  aws_networkfirewall as networkfirewall,
  aws_logs as logs,
} from "aws-cdk-lib";
import { Construct } from "constructs";

export class NetworkFirewallStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Get the string after the stack name in the stack id to append to the end of the Log Group name to make it unique
    const stackUniqueId = Fn.select(2, Fn.split("/", this.stackId));

    // CloudWatch Logs for VPC Flow Logs
    const vpcFlowLogsLogGroup = new logs.LogGroup(
      this,
      "VPC Flow Logs Log Group",
      {
        logGroupName: `/aws/vendedlogs/vpcFlowLogs-${stackUniqueId}`,
        retention: logs.RetentionDays.ONE_WEEK,
      }
    );

    // CloudWatch Logs for Network Firewall Flow Logs
    const networkFirewallFlowLogsLogGroup = new logs.LogGroup(
      this,
      "Network Firewall Flow Logs Log Group",
      {
        logGroupName: `/aws/vendedlogs/networkFirewallFlowLogs-${stackUniqueId}`,
        retention: logs.RetentionDays.ONE_WEEK,
      }
    );

    // CloudWatch Logs for Network Firewall Alert Logs
    const networkFirewallAlertLogsLogGroup = new logs.LogGroup(
      this,
      "Network Firewall Alert Logs Log Group",
      {
        logGroupName: `/aws/vendedlogs/networkFirewallAlertLogs-${stackUniqueId}`,
        retention: logs.RetentionDays.ONE_WEEK,
      }
    );

    // SSM IAM role
    const ssmIamRole = new iam.Role(this, "SSM IAM Role", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "AmazonSSMManagedInstanceCore"
        ),
      ],
    });

    // VPC Flow Logs IAM Role
    const vpcFlowLogsIamRole = new iam.Role(this, "VPC Flow Logs IAM Role", {
      assumedBy: new iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
      managedPolicies: [
        new iam.ManagedPolicy(this, "FlowLogsIamPolicy", {
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
              ],
              resources: [vpcFlowLogsLogGroup.logGroupArn],
            }),
          ],
        }),
      ],
    });

    //  VPC for inspection
    const inspectionVpc = new ec2.Vpc(this, "Inspection VPC", {
      cidr: "10.0.0.0/24",
      enableDnsHostnames: true,
      enableDnsSupport: true,
      maxAzs: 2,
      subnetConfiguration: [
        {
          name: "TgwAttachment",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
        {
          name: "Firewall",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
      ],
    });

    // Setting VPC Flow Logs for Inspection VPC
    new ec2.CfnFlowLog(this, "VPC Flow Log for Inspection VPC", {
      resourceId: inspectionVpc.vpcId,
      resourceType: "VPC",
      trafficType: "ALL",
      deliverLogsPermissionArn: vpcFlowLogsIamRole.roleArn,
      logDestination: vpcFlowLogsLogGroup.logGroupArn,
      logDestinationType: "cloud-watch-logs",
      logFormat:
        "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}",
      maxAggregationInterval: 60,
    });

    //  VPC for Egress
    const egressVpc = new ec2.Vpc(this, "Egress VPC", {
      cidr: "10.0.1.0/24",
      enableDnsHostnames: true,
      enableDnsSupport: true,
      maxAzs: 2,
      natGateways: 2,
      subnetConfiguration: [
        {
          name: "TgwAttachment",
          subnetType: ec2.SubnetType.PRIVATE_WITH_NAT,
          cidrMask: 28,
        },
        {
          name: "Public",
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 28,
        },
      ],
    });

    // Setting VPC Flow Logs for Egress VPC
    new ec2.CfnFlowLog(this, "VPC Flow Log for Egress VPC", {
      resourceId: egressVpc.vpcId,
      resourceType: "VPC",
      trafficType: "ALL",
      deliverLogsPermissionArn: vpcFlowLogsIamRole.roleArn,
      logDestination: vpcFlowLogsLogGroup.logGroupArn,
      logDestinationType: "cloud-watch-logs",
      logFormat:
        "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}",
      maxAggregationInterval: 60,
    });

    //  VPC for Spoke A
    const spokeVpcA = new ec2.Vpc(this, "Spoke VPC A", {
      cidr: "10.0.2.0/24",
      enableDnsHostnames: true,
      enableDnsSupport: true,
      maxAzs: 2,
      subnetConfiguration: [
        {
          name: "TgwAttachment",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
        {
          name: "Workload",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
      ],
    });

    // Setting VPC Flow Logs for Spoke VPC A
    new ec2.CfnFlowLog(this, "VPC Flow Log dor Spoke VPC A", {
      resourceId: spokeVpcA.vpcId,
      resourceType: "VPC",
      trafficType: "ALL",
      deliverLogsPermissionArn: vpcFlowLogsIamRole.roleArn,
      logDestination: vpcFlowLogsLogGroup.logGroupArn,
      logDestinationType: "cloud-watch-logs",
      logFormat:
        "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}",
      maxAggregationInterval: 60,
    });

    //  VPC for Spoke B
    const spokeVpcB = new ec2.Vpc(this, "Spoke VPC B", {
      cidr: "10.0.3.0/24",
      enableDnsHostnames: true,
      enableDnsSupport: true,
      maxAzs: 2,
      subnetConfiguration: [
        {
          name: "TgwAttachment",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
        {
          name: "Workload",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 28,
        },
      ],
    });

    // Setting VPC Flow Logs for Spoke VPC B
    new ec2.CfnFlowLog(this, "VPC Flow Log for Spoke VPC B", {
      resourceId: spokeVpcB.vpcId,
      resourceType: "VPC",
      trafficType: "ALL",
      deliverLogsPermissionArn: vpcFlowLogsIamRole.roleArn,
      logDestination: vpcFlowLogsLogGroup.logGroupArn,
      logDestinationType: "cloud-watch-logs",
      logFormat:
        "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}",
      maxAggregationInterval: 60,
    });

    // Transit Gateway
    const tgw = new ec2.CfnTransitGateway(this, "TGW", {
      defaultRouteTableAssociation: "disable",
      defaultRouteTablePropagation: "disable",
    });

    // Transit Gateway attachment for Inspection VPC
    const tgwAttachmentForInspectionVpc =
      new ec2.CfnTransitGatewayVpcAttachment(
        this,
        "TGW attachment for Inspection VPC",
        {
          subnetIds: inspectionVpc.selectSubnets({
            subnetGroupName: "TgwAttachment",
          }).subnetIds,
          transitGatewayId: tgw.attrId,
          vpcId: inspectionVpc.vpcId,
          options: {
            ApplianceModeSupport: "enable",
          },
          tags: [
            {
              key: "Name",
              value: "TGW attachment for Inspection VPC",
            },
          ],
        }
      );

    // Transit Gateway attachment for Egress VPC
    const tgwAttachmentForEgressVpc = new ec2.CfnTransitGatewayVpcAttachment(
      this,
      "TGW attachment for Egress VPC",
      {
        subnetIds: egressVpc.selectSubnets({
          subnetGroupName: "TgwAttachment",
        }).subnetIds,
        transitGatewayId: tgw.attrId,
        vpcId: egressVpc.vpcId,
        tags: [
          {
            key: "Name",
            value: "TGW attachment for Egress VPC",
          },
        ],
      }
    );

    // Transit Gateway attachment for Spoke VPC A
    const tgwAttachmentForSpokeVpcA = new ec2.CfnTransitGatewayVpcAttachment(
      this,
      "TGW attachment for Spoke VPC A",
      {
        subnetIds: spokeVpcA.selectSubnets({
          subnetGroupName: "TgwAttachment",
        }).subnetIds,
        transitGatewayId: tgw.attrId,
        vpcId: spokeVpcA.vpcId,
        tags: [
          {
            key: "Name",
            value: "TGW attachment for Spoke VPC A",
          },
        ],
      }
    );

    // Transit Gateway attachment for Spoke VPC B
    const tgwAttachmentForSpokeVpcB = new ec2.CfnTransitGatewayVpcAttachment(
      this,
      "TGW attachment for Spoke VPC B",
      {
        subnetIds: spokeVpcB.selectSubnets({
          subnetGroupName: "TgwAttachment",
        }).subnetIds,
        transitGatewayId: tgw.attrId,
        vpcId: spokeVpcB.vpcId,
        tags: [
          {
            key: "Name",
            value: "TGW attachment for Spoke VPC B",
          },
        ],
      }
    );

    // Transit Gateway route table for Inspection VPC
    const tgwRouteTableForInspectionVpc = new ec2.CfnTransitGatewayRouteTable(
      this,
      "TGW route table for Inspection VPC",
      {
        transitGatewayId: tgw.attrId,
        tags: [
          {
            key: "Name",
            value: "TGW route table for Inspection VPC",
          },
        ],
      }
    );

    // Associate Transit Gateway attachment for Inspection VPC
    new ec2.CfnTransitGatewayRouteTableAssociation(
      this,
      "TGW route table Association for Inspection VPC",
      {
        transitGatewayAttachmentId: tgwAttachmentForInspectionVpc.ref,
        transitGatewayRouteTableId: tgwRouteTableForInspectionVpc.ref,
      }
    );

    // Route Inspection VPC To Egress VPC
    new ec2.CfnTransitGatewayRoute(
      this,
      "TGW route Inspection VPC to Egress VPC",
      {
        transitGatewayAttachmentId: tgwAttachmentForEgressVpc.ref,
        transitGatewayRouteTableId: tgwRouteTableForInspectionVpc.ref,
        destinationCidrBlock: "0.0.0.0/0",
      }
    );

    // Route Inspection VPC To Spoke VPC A
    new ec2.CfnTransitGatewayRoute(
      this,
      "TGW route Inspection VPC to Spoke VPC A",
      {
        transitGatewayAttachmentId: tgwAttachmentForSpokeVpcA.ref,
        transitGatewayRouteTableId: tgwRouteTableForInspectionVpc.ref,
        destinationCidrBlock: spokeVpcA.vpcCidrBlock,
      }
    );

    // Route Inspection VPC To Spoke VPC B
    new ec2.CfnTransitGatewayRoute(
      this,
      "TGW route Inspection VPC to Spoke VPC B",
      {
        transitGatewayAttachmentId: tgwAttachmentForSpokeVpcB.ref,
        transitGatewayRouteTableId: tgwRouteTableForInspectionVpc.ref,
        destinationCidrBlock: spokeVpcB.vpcCidrBlock,
      }
    );

    // Transit Gateway route table for Egress VPC
    const tgwRouteTableForEgressVpc = new ec2.CfnTransitGatewayRouteTable(
      this,
      "TGW route table for Egress VPC",
      {
        transitGatewayId: tgw.attrId,
        tags: [
          {
            key: "Name",
            value: "TGW route table for Egress VPC",
          },
        ],
      }
    );

    // Associate Transit Gateway attachment for Egress VPC
    new ec2.CfnTransitGatewayRouteTableAssociation(
      this,
      "TGW route table association for Egress VPC",
      {
        transitGatewayAttachmentId: tgwAttachmentForEgressVpc.ref,
        transitGatewayRouteTableId: tgwRouteTableForEgressVpc.ref,
      }
    );

    // Route Egress VPC To Inspection VPC
    new ec2.CfnTransitGatewayRoute(
      this,
      "TGW route Egress VPC to Inspection VPC",
      {
        transitGatewayAttachmentId: tgwAttachmentForInspectionVpc.ref,
        transitGatewayRouteTableId: tgwRouteTableForEgressVpc.ref,
        destinationCidrBlock: "0.0.0.0/0",
      }
    );

    // Transit Gateway route table for Spoke VPC A
    const tgwRouteTableForSpokeVpcA = new ec2.CfnTransitGatewayRouteTable(
      this,
      "TGW route table for Spoke VPC A",
      {
        transitGatewayId: tgw.attrId,
        tags: [
          {
            key: "Name",
            value: "TGW route table for Spoke VPC A",
          },
        ],
      }
    );

    // Associate Transit Gateway attachment for Spoke VPC A
    new ec2.CfnTransitGatewayRouteTableAssociation(
      this,
      "TGW route table association for Spoke VPC A",
      {
        transitGatewayAttachmentId: tgwAttachmentForSpokeVpcA.ref,
        transitGatewayRouteTableId: tgwRouteTableForSpokeVpcA.ref,
      }
    );

    // Route Spoke VPC A To Inspection VPC
    new ec2.CfnTransitGatewayRoute(
      this,
      "TGW route Spoke VPC A to Inspection VPC",
      {
        transitGatewayAttachmentId: tgwAttachmentForInspectionVpc.ref,
        transitGatewayRouteTableId: tgwRouteTableForSpokeVpcA.ref,
        destinationCidrBlock: "0.0.0.0/0",
      }
    );

    // Transit Gateway route table for Spoke VPC B
    const tgwRouteTableForSpokeVpcB = new ec2.CfnTransitGatewayRouteTable(
      this,
      "TGW route table for Spoke VPC B",
      {
        transitGatewayId: tgw.attrId,
        tags: [
          {
            key: "Name",
            value: "TGW route table for Spoke VPC B",
          },
        ],
      }
    );

    // Associate Transit Gateway attachment for Spoke VPC B
    new ec2.CfnTransitGatewayRouteTableAssociation(
      this,
      "TGW route table association forSpokeVpcB",
      {
        transitGatewayAttachmentId: tgwAttachmentForSpokeVpcB.ref,
        transitGatewayRouteTableId: tgwRouteTableForSpokeVpcB.ref,
      }
    );

    // Route Spoke VPC B To Inspection VPC
    new ec2.CfnTransitGatewayRoute(
      this,
      "TGW route Spoke VPC B to Inspection VPC",
      {
        transitGatewayAttachmentId: tgwAttachmentForInspectionVpc.ref,
        transitGatewayRouteTableId: tgwRouteTableForSpokeVpcB.ref,
        destinationCidrBlock: "0.0.0.0/0",
      }
    );

    // Network Firewall rule group
    const icmpStatefulRuleGroup = new networkfirewall.CfnRuleGroup(
      this,
      "ICMP Stateful Rule Group",
      {
        capacity: 100,
        ruleGroupName: "icmp",
        type: "STATEFUL",
        ruleGroup: {
          rulesSource: {
            statefulRules: [
              {
                action: "ALERT",
                header: {
                  destination: "10.0.0.0/16",
                  destinationPort: "ANY",
                  direction: "ANY",
                  protocol: "ICMP",
                  source: "10.0.0.0/16",
                  sourcePort: "ANY",
                },
                ruleOptions: [
                  {
                    keyword: `msg:"icmp alert"`,
                  },
                  {
                    keyword: "sid:1000001",
                  },
                  {
                    keyword: "rev:1",
                  },
                ],
              },
            ],
          },
        },
      }
    );

    // Network Firewall policy
    const networkfirewallPolicy = new networkfirewall.CfnFirewallPolicy(
      this,
      "Network Firewall Policy",
      {
        firewallPolicyName: "InspectionPolicy",
        firewallPolicy: {
          statelessDefaultActions: ["aws:forward_to_sfe"],
          statelessFragmentDefaultActions: ["aws:forward_to_sfe"],
          statefulRuleGroupReferences: [
            {
              resourceArn: icmpStatefulRuleGroup.attrRuleGroupArn,
            },
          ],
        },
      }
    );

    // Network Firewall
    const networkFirewall = new networkfirewall.CfnFirewall(
      this,
      "Network Firewall",
      {
        firewallName: "NetworkFirewall",
        firewallPolicyArn: networkfirewallPolicy.attrFirewallPolicyArn,
        vpcId: inspectionVpc.vpcId,
        subnetMappings: (() => {
          const firewallSubnetIds: { subnetId: string }[] = new Array();
          inspectionVpc
            .selectSubnets({ subnetGroupName: "Firewall" })
            .subnets.forEach((subnet) => {
              firewallSubnetIds.push({ subnetId: subnet.subnetId });
            });
          return firewallSubnetIds;
        })(),
      }
    );

    // // Setting Network Firewall logs
    new networkfirewall.CfnLoggingConfiguration(this, "Network Firewall Logs", {
      firewallArn: networkFirewall.ref,
      loggingConfiguration: {
        logDestinationConfigs: [
          {
            logDestination: {
              logGroup: networkFirewallFlowLogsLogGroup.logGroupName,
            },
            logDestinationType: "CloudWatchLogs",
            logType: "FLOW",
          },
          {
            logDestination: {
              logGroup: networkFirewallAlertLogsLogGroup.logGroupName,
            },
            logDestinationType: "CloudWatchLogs",
            logType: "ALERT",
          },
        ],
      },
    });

    // Route Inspection VPC to Transit Gateway
    inspectionVpc
      .selectSubnets({ subnetGroupName: "Firewall" })
      .subnets.map((subnet, index) => {
        new ec2.CfnRoute(this, `Inspection VPC route to TGW ${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: "0.0.0.0/0",
          transitGatewayId: tgw.ref,
        }).addDependsOn(tgwAttachmentForInspectionVpc);
      });

    // Route Egress VPC to Transit Gateway
    egressVpc
      .selectSubnets({ subnetGroupName: "Public" })
      .subnets.map((subnet, index) => {
        new ec2.CfnRoute(this, `Egress VPC route to TGW ${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: "10.0.0.0/16",
          transitGatewayId: tgw.ref,
        }).addDependsOn(tgwAttachmentForEgressVpc);
      });

    // Route Spoke VPC A to Transit Gateway
    spokeVpcA
      .selectSubnets({ subnetGroupName: "Workload" })
      .subnets.map((subnet, index) => {
        new ec2.CfnRoute(this, `Spoke VPC A route to TGW ${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: "0.0.0.0/0",
          transitGatewayId: tgw.ref,
        }).addDependsOn(tgwAttachmentForSpokeVpcA);
      });

    // Route Spoke VPC B to Transit Gateway
    spokeVpcB
      .selectSubnets({ subnetGroupName: "Workload" })
      .subnets.map((subnet, index) => {
        new ec2.CfnRoute(this, `Spoke VPC B route to TGW ${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: "0.0.0.0/0",
          transitGatewayId: tgw.ref,
        }).addDependsOn(tgwAttachmentForSpokeVpcB);
      });

    // Route Inspection VPC to Network Firewall
    inspectionVpc
      .selectSubnets({ subnetGroupName: "TgwAttachment" })
      .subnets.map((subnet, index) => {
        new ec2.CfnRoute(
          this,
          `Inspection VPC route to Network Firewall ${index}`,
          {
            routeTableId: subnet.routeTable.routeTableId,
            destinationCidrBlock: "0.0.0.0/0",
            vpcEndpointId: Fn.select(
              1,
              Fn.split(":", Fn.select(index, networkFirewall.attrEndpointIds))
            ),
          }
        ).addDependsOn(networkFirewall);
      });

    // Security Group
    const spokeVpcASg = new ec2.SecurityGroup(this, "Spoke VPC A SG", {
      allowAllOutbound: true,
      vpc: spokeVpcA,
    });
    spokeVpcASg.addIngressRule(
      ec2.Peer.ipv4("10.0.0.0/16"),
      ec2.Port.allTraffic()
    );

    const spokeVpcBSg = new ec2.SecurityGroup(this, "Spoke VPC B SG", {
      allowAllOutbound: true,
      vpc: spokeVpcB,
    });
    spokeVpcBSg.addIngressRule(
      ec2.Peer.ipv4("10.0.0.0/16"),
      ec2.Port.allTraffic()
    );

    // EC2 instance
    spokeVpcA
      .selectSubnets({ subnetGroupName: "Workload" })
      .subnets.map((subnet, index) => {
        new ec2.Instance(this, `Spoke VPC A EC2 Instance ${index}`, {
          machineImage: ec2.MachineImage.latestAmazonLinux({
            generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
          }),
          instanceType: new ec2.InstanceType("t3.micro"),
          vpc: spokeVpcA,
          vpcSubnets: spokeVpcA.selectSubnets({
            subnetGroupName: "Workload",
            availabilityZones: [spokeVpcA.availabilityZones[index]],
          }),
          securityGroup: spokeVpcASg,
          role: ssmIamRole,
          blockDevices: [
            {
              deviceName: "/dev/xvda",
              volume: ec2.BlockDeviceVolume.ebs(8, {
                volumeType: ec2.EbsDeviceVolumeType.GP3,
              }),
            },
          ],
          propagateTagsToVolumeOnCreation: true,
        });
      });

    spokeVpcB
      .selectSubnets({ subnetGroupName: "Workload" })
      .subnets.map((subnet, index) => {
        new ec2.Instance(this, `Spoke VPC B EC2 Instance ${index}`, {
          machineImage: ec2.MachineImage.latestAmazonLinux({
            generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
          }),
          instanceType: new ec2.InstanceType("t3.micro"),
          vpc: spokeVpcB,
          vpcSubnets: spokeVpcB.selectSubnets({
            subnetGroupName: "Workload",
            availabilityZones: [spokeVpcB.availabilityZones[index]],
          }),
          securityGroup: spokeVpcBSg,
          role: ssmIamRole,
          blockDevices: [
            {
              deviceName: "/dev/xvda",
              volume: ec2.BlockDeviceVolume.ebs(8, {
                volumeType: ec2.EbsDeviceVolumeType.GP3,
              }),
            },
          ],
          propagateTagsToVolumeOnCreation: true,
        });
      });
  }
}
