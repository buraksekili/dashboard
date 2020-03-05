import {NodeProvider} from '../model/NodeProviderConstants';

import {AlibabaCloudSpec} from './cloud/AlibabaCloudSpec';
import {AWSCloudSpec} from './cloud/AWSCloudSpec';
import {AzureCloudSpec} from './cloud/AzureCloudSpec';
import {BareMetalCloudSpec} from './cloud/BareMetalCloudSpec';
import {BringYourOwnCloudSpec} from './cloud/BringYourOwnCloudSpec';
import {DigitaloceanCloudSpec} from './cloud/DigitaloceanCloudSpec';
import {FakeCloudSpec} from './cloud/FakeCloudSpec';
import {GCPCloudSpec} from './cloud/GCPCloudSpec';
import {HetznerCloudSpec} from './cloud/HetznerCloudSpec';
import {KubeVirtCloudSpec} from './cloud/KubeVirtCloudSpec';
import {OpenstackCloudSpec} from './cloud/OpenstackCloudSpec';
import {PacketCloudSpec} from './cloud/PacketCloudSpec';
import {VSphereCloudSpec} from './cloud/VSphereCloudSpec';

export function getClusterProvider(cluster: ClusterEntity): NodeProvider {
  const clusterProviders = Object.values(NodeProvider)
                               .map(provider => cluster.spec.cloud[provider] ? provider : undefined)
                               .filter(p => p !== undefined);

  return clusterProviders.length > 0 ? clusterProviders[0] : NodeProvider.NONE;
}

export const enum Finalizer {
  DeleteVolumes = 'DeleteVolumes',
  DeleteLoadBalancers = 'DeleteLoadBalancers',
}

export class ClusterEntity {
  creationTimestamp?: Date;
  deletionTimestamp?: Date;
  id?: string;
  name: string;
  spec: ClusterSpec;
  status?: Status;
  type: string;
  labels?: object;
  inheritedLabels?: object;
  credential?: string;
}

export function getEmptyCloudProviderSpec(provider: NodeProvider): object {
  switch (provider) {
    case NodeProvider.AWS:
      return {
        accessKeyId: '',
        secretAccessKey: '',
        routeTableId: '',
        vpcId: '',
        securityGroupID: '',
        instanceProfileName: '',
        roleARN: '',
      } as AWSCloudSpec;
    case NodeProvider.DIGITALOCEAN:
      return {
        token: '',
      } as DigitaloceanCloudSpec;
    case NodeProvider.BAREMETAL:
      return {
        name: '',
      } as BareMetalCloudSpec;
    case NodeProvider.OPENSTACK:
      return {
        username: '',
        password: '',
        floatingIpPool: '',
        securityGroups: '',
        network: '',
        domain: '',
        tenant: '',
        tenantID: '',
        subnetID: '',
      } as OpenstackCloudSpec;
    case NodeProvider.BRINGYOUROWN:
      return {} as BringYourOwnCloudSpec;
    case NodeProvider.VSPHERE:
      return {
        username: '',
        password: '',
        vmNetName: '',
        folder: '',
        infraManagementUser: {
          username: '',
          password: '',
        },
      } as VSphereCloudSpec;
    case NodeProvider.HETZNER:
      return {
        token: '',
      } as HetznerCloudSpec;
    case NodeProvider.AZURE:
      return {
        clientID: '',
        clientSecret: '',
        resourceGroup: '',
        routeTable: '',
        securityGroup: '',
        subnet: '',
        subscriptionID: '',
        tenantID: '',
        vnet: '',
      } as AzureCloudSpec;
    case NodeProvider.PACKET:
      return {} as PacketCloudSpec;
    case NodeProvider.KUBEVIRT:
      return {kubeconfig: ''} as KubeVirtCloudSpec;
    case NodeProvider.GCP:
      return {
        network: '',
        serviceAccount: '',
        subnetwork: '',
      } as GCPCloudSpec;
    case NodeProvider.ALIBABA:
      return {
        accessKeyID: '',
        accessKeySecret: '',
      } as AlibabaCloudSpec;
  }
  return {};
}

export class CloudSpec {
  dc: string;
  digitalocean?: DigitaloceanCloudSpec;
  aws?: AWSCloudSpec;
  bringyourown?: BringYourOwnCloudSpec;
  openstack?: OpenstackCloudSpec;
  packet?: PacketCloudSpec;
  baremetal?: BareMetalCloudSpec;
  vsphere?: VSphereCloudSpec;
  hetzner?: HetznerCloudSpec;
  azure?: AzureCloudSpec;
  fake?: FakeCloudSpec;
  gcp?: GCPCloudSpec;
  kubevirt?: KubeVirtCloudSpec;
  alibaba?: AlibabaCloudSpec;
}

export class ClusterSpec {
  cloud: CloudSpec;
  machineNetworks?: MachineNetwork[];
  auditLogging?: AuditLoggingSettings;
  version?: string;
  usePodSecurityPolicyAdmissionPlugin?: boolean;
  usePodNodeSelectorAdmissionPlugin?: boolean;
  openshift?: OpenShift;
}

export class AuditLoggingSettings {
  enabled?: boolean;
}

export class OpenShift {
  imagePullSecret?: string;
}

export class MachineNetwork {
  cidr: string;
  dnsServers: string[];
  gateway: string;
}

export class Status {
  url: string;
  version: string;
}

export class MasterVersion {
  version: string;
  default?: boolean;
  restrictedByKubeletVersion?: boolean;
}

export class Token {
  token: string;
}
