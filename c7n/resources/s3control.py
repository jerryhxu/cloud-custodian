# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.actions import Action
from c7n.filters.iamaccess import CrossAccountAccessFilter
from c7n.manager import resources
from c7n.resources.aws import Arn
from c7n.query import QueryResourceManager, TypeInfo, DescribeSource
from c7n.utils import local_session, type_schema
from c7n.tags import RemoveTag, Tag, TagActionFilter, TagDelayedAction
from c7n.actions import BaseAction


class AccessPointDescribe(DescribeSource):
    def get_query_params(self, query_params):
        query_params = query_params or {}
        query_params['AccountId'] = self.manager.config.account_id
        return query_params

    def augment(self, resources):
        client = local_session(self.manager.session_factory).client('s3control')
        results = []
        for r in resources:
            arn = Arn.parse(r['AccessPointArn'])
            ap = client.get_access_point(AccountId=arn.account_id, Name=r['Name'])
            ap.pop('ResponseMetadata', None)
            ap['AccessPointArn'] = arn.arn
            results.append(ap)
        return results


@resources.register('s3-access-point')
class AccessPoint(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 's3control'
        id = name = 'Name'
        enum_spec = ('list_access_points', 'AccessPointList', None)
        arn = 'AccessPointArn'
        arn_service = 's3'
        arn_type = 'accesspoint'
        cfn_type = 'AWS::S3::AccessPoint'
        permission_prefix = 's3'

    source_mapping = {'describe': AccessPointDescribe}


@AccessPoint.filter_registry.register('cross-account')
class AccessPointCrossAccount(CrossAccountAccessFilter):

    policy_attribute = 'c7n:Policy'
    permissions = ('s3:GetAccessPointPolicy',)

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client('s3control')
        for r in resources:
            if self.policy_attribute in r:
                continue
            arn = Arn.parse(r['AccessPointArn'])
            r[self.policy_attribute] = client.get_access_point_policy(
                AccountId=arn.account_id, Name=r['Name']
            ).get('Policy')

        return super().process(resources, event)


@AccessPoint.action_registry.register('delete')
class Delete(Action):

    schema = type_schema('delete')
    permissions = ('s3:DeleteAccessPoint',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('s3control')
        for r in resources:
            arn = Arn.parse(r['AccessPointArn'])
            try:
                client.delete_access_point(AccountId=arn.account_id, Name=r['Name'])
            except client.NotFoundException:
                continue


class MultiRegionAccessPointDescribe(DescribeSource):
    def get_query_params(self, query_params):
        query_params = query_params or {}
        query_params['AccountId'] = self.manager.config.account_id
        return query_params


@resources.register('s3-access-point-multi')
class MultiRegionAccessPoint(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 's3control'
        id = name = 'Name'
        enum_spec = ('list_multi_region_access_points', 'AccessPoints', None)
        arn_service = 's3'
        arn_type = 'accesspoint'
        cfn_type = 'AWS::S3::MultiRegionAccessPoint'
        permission_prefix = 's3'

    source_mapping = {'describe': MultiRegionAccessPointDescribe}


class StorageLensDescribe(DescribeSource):
    def get_query_params(self, query_params):
        query_params = query_params or {}
        query_params['AccountId'] = self.manager.config.account_id
        return query_params

    def augment(self, resources):
        client = local_session(self.manager.session_factory).client('s3control')
        results = []
        for r in resources:
            arn = Arn.parse(r['StorageLensArn'])
            storage_lens_configuration = client.get_storage_lens_configuration(AccountId=arn.account_id, ConfigId=r['Id'])
            storage_lens_configuration.pop('ResponseMetadata', None)
            tags = client.get_storage_lens_configuration_tagging(AccountId=arn.account_id, ConfigId=r['Id'])
            r['Tags'] = tags['Tags']
            results.append(storage_lens_configuration)
        return results


@resources.register('s3-storage-lens')
class StorageLens(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 's3control'
        id = name = 'Id'
        enum_spec = ('list_storage_lens_configurations', 'StorageLensConfigurationList', None)
        arn = 'StorageLensArn'
        arn_service = 's3'
        arn_type = 'storage-lens'
        cfn_type = 'AWS::S3::StorageLens'
        permission_prefix = 's3'        

    source_mapping = {'describe': StorageLensDescribe}


def modify_storage_lens_tags(client, configId, accountId, add_tags={}, remove_tags={}):
    existing_tags = client.get_storage_lens_configuration_tagging(
            AccountId=accountId, 
            ConfigId=configId)

    if len(add_tags) > 0:
        new_tags = {t['Key']: t['Value'] for t in add_tags}
        for t in existing_tags:
            if t['Key'] not in new_tags and t['Key'] not in remove_tags:
                new_tags[t['Key']] = t['Value']
    
    if len(remove_tags) > 0:
        for t in existing_tags:
            if t['Key'] not in remove_tags:
                new_tags[t['Key']] = t['Value']
    #tags = [{'Key': k, 'Value': v} for k, v in new_tags.items()]

    client.put_storage_lens_configuration_tagging(
        AccountId=accountId,
        configId=configId,
        Tags=new_tags)


@StorageLens.action_registry.register('tag')
class TagStorageLens(Tag):
    """Create tags on s3 storage lens

    :example:

    .. code-block:: yaml

        policies:
            - name: s3-storage-lens-tag
              resource: aws.s3-storage-lens
              actions:
                - type: tag
                  key: test
                  value: storagelens
    """
    permissions = ('s3:TagResource',)

    def process_resource_set(self, client, resources, add_tags):
        accountId=self.manager.config.account_id
        for r in resources:
            configId=r['StorageLensConfiguration']['Id']
            existing_tags = client.get_storage_lens_configuration_tagging(
                AccountId=accountId, 
                ConfigId=configId)
            new_tags = {t['Key']: t['Value'] for t in add_tags}
            for t in existing_tags['Tags']:
                if t['Key'] not in new_tags:
                    new_tags[t['Key']] = t['Value']
            tags = [{'Key': k, 'Value': v} for k, v in new_tags.items()]
            client.put_storage_lens_configuration_tagging(
                AccountId=accountId,
                ConfigId=configId,
                Tags=tags)
            

@StorageLens.action_registry.register('remove-tag')
class RemoveTagStorageLens(RemoveTag):
    """Remove tags from a storage lens configuration
    :example:

    .. code-block:: yaml

        policies:
            - name: storage-lens-remove-tag
              resource: aws.s3-storage-lens
              actions:
                - type: remove-tag
                  tags: ["tag-key"]
    """
    permissions = ('s3:UntagResource',)

    def process_resource_set(self, client, resources, remove_tags):
        accountId=self.manager.config.account_id
        for r in resources:
            configId=r['StorageLensConfiguration']['Id']
            existing_tags = client.get_storage_lens_configuration_tagging(
                AccountId=accountId, 
                ConfigId=configId)
            new_tags = {}
            for t in existing_tags['Tags']:
                if t['Key'] not in remove_tags:
                    new_tags[t['Key']] = t['Value']
            tags = [{'Key': k, 'Value': v} for k, v in new_tags.items()]
            client.put_storage_lens_configuration_tagging(
                AccountId=accountId,
                ConfigId=configId,
                Tags=tags)


@StorageLens.action_registry.register('delete')
class DeleteStorageLens(BaseAction):
    """Delete a storage lens configuration

    :example:

    .. code-block:: yaml

        policies:
          - name: storage-lens-delete
            resource: aws.s3-storage-lens
            actions:
              - type: delete
    """
    schema = type_schema('delete')
    permissions = ('s3:DeleteStorageLensConfiguration',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('s3control')
        accountId=self.manager.config.account_id
        for r in resources:
            configId=r['StorageLensConfiguration']['Id']
            client.delete_storage_lens_configuration(
                ConfigId=configId,
                AccountId=accountId
            )

