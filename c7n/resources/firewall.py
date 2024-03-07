# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from .aws import AWS
from c7n.query import (
    QueryResourceManager, TypeInfo, DescribeSource, ConfigSource)
from c7n.filters.vpc import VpcFilter, SubnetFilter
from c7n.filters import ListItemFilter, FilterRegistry
from c7n.actions import ActionRegistry, BaseAction
from c7n.utils import local_session, type_schema
from .aws import shape_validate
from c7n.tags import RemoveTag, Tag, TagActionFilter, TagDelayedAction

filters = FilterRegistry('aws.account.filters')
actions = ActionRegistry('aws.account.actions')

class FirewallDescribe(DescribeSource):

    def augment(self, resources):
        resources = super().augment(resources)
        augmented_resources = []
        for r in resources:
            status = r.pop('FirewallStatus', {})
            r['Firewall']['UpdateToken'] = r['UpdateToken']
            ar = r.pop('Firewall')
            ar['FirewallStatus'] = status
            augmented_resources.append(ar)
        return augmented_resources


class FirewallConfig(ConfigSource):

    def load_resource(self, item):
        resource = super().load_resource(item)
        resource.update(resource.pop('Firewall'))
        return resource


@AWS.resources.register('firewall')
class NetworkFirewall(QueryResourceManager):
    """AWS Network Firewall

    https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html
    """
    source_mapping = {
        'describe': FirewallDescribe,
        'config': FirewallConfig
    }

    class resource_type(TypeInfo):

        service = 'network-firewall'
        enum_spec = ('list_firewalls', 'Firewalls', None)
        arn = 'FirewallArn'
        arn_type = 'firewall'
        detail_spec = ('describe_firewall', 'FirewallArn', 'FirewallArn', '')
        id = name = 'FirewallName'
        cfn_type = config_type = 'AWS::NetworkFirewall::Firewall'
        metrics_namespace = 'AWS/NetworkFirewall'
        universal_taggable = object()


@NetworkFirewall.filter_registry.register('vpc')
class FirewallVpcFilter(VpcFilter):

    RelatedIdsExpression = 'VpcId'


@NetworkFirewall.filter_registry.register('subnet')
class FirewallSubnetFilter(SubnetFilter):

    RelatedIdsExpression = 'SubnetMappings[].SubnetId'

@NetworkFirewall.action_registry.register('tag')
class TagNetworkFirewall(Tag):
    """Create tags on Network Firewalls

    :example:

    .. code-block:: yaml

        policies:
            - name: network-firewall-tag
              resource: aws.firewall
              actions:
                - type: tag
                  key: test
                  value: something
    """
    permissions = ('network-firewall:TagResource',)

    def process_resource_set(self, client, resources, new_tags):
        #tags = [{'key': item['Key'], 'value': item['Value']} for item in new_tags]
        for r in resources:
            client.tag_resource(ResourceArn=r["FirewallArn"], Tags=new_tags)


@NetworkFirewall.action_registry.register('remove-tag')
class RemoveNetworkFirewall(RemoveTag):
    """Remove tags from a network firewall
    :example:

    .. code-block:: yaml

        policies:
            - name: network-firewall-remove-tag
              resource: aws.firewall
              actions:
                - type: remove-tag
                  tags: ["tag-key"]
    """
    permissions = ('network-firewall:UntagResource',)

    def process_resource_set(self, client, resources, tags):
        for r in resources:
            client.untag_resource(ResourceArn=r['FirewallArn'], TagKeys=tags)


NetworkFirewall.filter_registry.register('marked-for-op', TagActionFilter)
@NetworkFirewall.action_registry.register('mark-for-op')
class MarkNetworkFirewallForOp(TagDelayedAction):
    """Mark network firewall for future actions

    :example:

    .. code-block:: yaml

        policies:
          - name: network-firewall-tag-mark
            resource: aws.firewall
            filters:
              - "tag:delete": present
            actions:
              - type: mark-for-op
                op: delete
                days: 1
    """

@NetworkFirewall.filter_registry.register('logging')
class NetworkFirewallLogging(ListItemFilter):
    """Filter for network firewall to look at network firewall logging configuration

    The schema to supply to the attrs follows the schema here:
     https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/network-firewall/client/describe_logging_configuration.html

    :example:

    .. code-block:: yaml

            policies:
              - name: network-firewall-logging-configuration
                resource: aws.network-firewall
                filters:
                #   - type: logging
                #     attrs:
                #       - LogType: ALERT
                  - type: logging
                    attrs:
                      - LogType: FLOW
    """
    schema = type_schema(
        'logging',
        attrs={'$ref': '#/definitions/filters_common/list_item_attrs'},
        count={'type': 'number'},
        count_op={'$ref': '#/definitions/filters_common/comparison_operators'}
    )
    permissions = ('network-firewall:DescribeLoggingConfiguration',)
    annotation_key = 'c7n:NetworkFirewall'

    def get_item_values(self, resource):
        client = local_session(self.manager.session_factory).client('network-firewall')
        resource[self.annotation_key] = client \
                .describe_logging_configuration(
                    FirewallArn=resource['FirewallArn'],
                    FirewallName=resource['FirewallName'])\
                .get('LoggingConfiguration', {}).get('LogDestinationConfigs', [])

        return resource.get(self.annotation_key)


@NetworkFirewall.action_registry.register('delete')
class DeleteNetworkFirewall(BaseAction):
    """Delete a network firewall

    :example:

    .. code-block:: yaml

        policies:
          - name: network-firewall-delete
            resource: aws.firewall
            actions:
              - type: delete
    """
    schema = type_schema('delete', )
    permissions = ('network-firewall:DeleteFirewall',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('network-firewall')
        for r in resources:
            try:
              client.delete_firewall(
                  FirewallName=r['FirewallName'],
                  FirewallArn =r['FirewallArn']
                  )
            except client.exceptions.ResourceNotFoundException:
              continue


@NetworkFirewall.action_registry.register('update-delete-protection')
class UpdateNetworkFirewall(BaseAction):
    """Enable/disable network firewall delete protection."""

    permissions = ('network-firewall:UpdateFirewallDeleteProtection',)

    schema = type_schema(
        'update-delete-protection',
        state={'type': 'boolean'})

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('network-firewall')
        state = self.data.get('state', True)
        for r in resources:
            try:
                client.update_firewall_delete_protection(
                    FirewallName=r['FirewallName'],
                    FirewallArn =r['FirewallArn'],
                    DeleteProtection = state
                    )
            except client.exceptions.ResourceNotFoundException:
                continue