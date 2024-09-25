# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest
from unittest.mock import MagicMock
import time


class GlobalAcceleratorTest(BaseTest):

    def test_globalaccelerator_tag_untag(self):
        session_factory = self.replay_flight_data('test_globalaccelerator_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'globalaccelerator-tag-untag',
                'resource': 'globalaccelerator',
                'filters': [{
                    'tag:owner': 'policy'
                }],
                'actions': [{
                    'type': 'tag',
                    'tags': tag
                },
                {
                    'type': 'remove-tag',
                    'tags': ['owner']
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        client = session_factory(region="us-west-2").client("globalaccelerator")
        tags = client.list_tags_for_resource(ResourceArn=resources[0]["AcceleratorArn"])["Tags"]
        self.assertEqual(1, len(tags))
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_globalaccelerator_mark_for_op(self):
        session_factory = self.replay_flight_data("test_globalaccelerator_mark_for_op")
        p = self.load_policy(
            {
                "name": "globalaccelerator-mark",
                "resource": "globalaccelerator",
                "filters": [
                    {'tag:owner': 'policy'},
                ],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "days": 1,
                    }
                ],
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        p = self.load_policy(
            {
                "name": "globalaccelerator-marked",
                "resource": "globalaccelerator",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "skew": 3,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-custodian'

    def test_delete_globalaccelerator(self):
        session_factory = self.record_flight_data("test_delete_globalaccelerator")
        p = self.load_policy(
            {
                "name": "delete-globalaccelerator",
                "resource": "globalaccelerator",
                "filters": [{"tag:owner": "delete"}],
                "actions": [{
                                "type": "delete",
                            }],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual(resources[0]["Name"], "test-accelerator-2")

    def test_delete_globalaccelerator_exception(self):
        factory = self.replay_flight_data("test_delete_globalaccelerator")
        client = factory().client("globalaccelerator")
        mock_factory = MagicMock()
        mock_factory.region = 'us-east-1'
        mock_factory().client(
            'globalaccelerator').exceptions.ClusterNotFoundFault = (
                client.exceptions.ClusterNotFoundFault)
        mock_factory().client('globalaccelerator').delete_cluster.side_effect = (
            client.exceptions.ClusterNotFoundFault(
                {'Error': {'Code': 'xyz'}},
                operation_name='delete_cluster'))
        p = self.load_policy({
            'name': 'delete-globalaccelerator-exception',
            'resource': 'globalaccelerator',
            "filters": [{"tag:owner": "policy"}],
            'actions': [{
                            "type": "delete",
                        }],
            },
            session_factory=mock_factory)

        try:
            p.resource_manager.actions[0].process(
                [{'Name': 'abc'}])
        except client.exceptions.ClusterNotFoundFault:
            self.fail('should not raise')
        mock_factory().client('globalaccelerator').delete_cluster.assert_called_once()

    def test_globalaccelerator_security_group(self):
        session_factory = self.replay_flight_data("test_globalaccelerator_security_group")
        p = self.load_policy(
            {
                "name": "globalaccelerator-security-group",
                "resource": "globalaccelerator",
                "filters": [
                    {"type": "security-group", "key": "tag:ASV", "value": "PolicyTest"}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-cluster-custodian'

    def test_globalaccelerator_subnet_filter(self):
        session_factory = self.replay_flight_data(
            "test_globalaccelerator_subnet_filter"
        )
        p = self.load_policy(
            {
                "name": "globalaccelerator-subnet-filter",
                "resource": "globalaccelerator",
                "filters": [
                    {"type": "subnet", "key": "tag:Name", "value": "PublicSubnetA"}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-cluster-custodian'

    def test_globalaccelerator_network_location_filter(self):
        factory = self.replay_flight_data("test_globalaccelerator_network_location_filter")

        p = self.load_policy(
            {
                "name": "test_globalaccelerator_network_location_filter",
                "resource": "globalaccelerator",
                "filters": [
                    {
                        "type": "network-location",
                        "compare": ["resource", "subnet"],
                        "key": "tag:ASV",
                        "match": "equal"
                    }
                ]
            },
            session_factory=factory
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-cluster-custodian'

    def test_globalaccelerator_kms_encryption(self):
        session_factory = self.replay_flight_data('test_globalaccelerator_kms_encryption')
        p = self.load_policy(
            {
                'name': 'globalaccelerator-kms-encryption',
                'resource': 'globalaccelerator',
                'filters': [
                    {
                        'type': 'kms-key',
                        'key': 'c7n:AliasName',
                        'value': 'alias/tes/pratyush',
                    }
                ],
            }, session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['Name'], 'test-cluster-2')

    def test_globalaccelerator_snapshot(self):
        factory = self.replay_flight_data("test_memory_db_snapshot")
        p = self.load_policy({
            'name': 'globalaccelerator-snapshot',
            'resource': 'aws.globalaccelerator-snapshot'},
            session_factory=factory,
            config={'region': 'us-east-1'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-snapshot-2'

    def test_globalaccelerator_snapshot_tag_untag(self):
        session_factory = self.replay_flight_data('test_globalaccelerator_snapshot_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'globalaccelerator-tag-untag',
                'resource': 'globalaccelerator-snapshot',
                'filters': [{
                    'tag:owner': 'policy'
                }],
                'actions': [{
                    'type': 'tag',
                    'tags': tag
                },
                {
                    'type': 'remove-tag',
                    'tags': ['owner']
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        client = session_factory().client("globalaccelerator")
        tags = client.list_tags(ResourceArn=resources[0]["ARN"])["TagList"]
        self.assertEqual(1, len(tags))
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_globalaccelerator_snapshot_mark_for_op(self):
        session_factory = self.replay_flight_data("test_globalaccelerator_snapshot_mark_for_op")
        p = self.load_policy(
            {
                "name": "globalaccelerator-snapshot-mark",
                "resource": "globalaccelerator-snapshot",
                "filters": [
                    {'tag:owner': 'policy'},
                ],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "days": 1,
                    }
                ],
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        p = self.load_policy(
            {
                "name": "globalaccelerator-marked",
                "resource": "globalaccelerator-snapshot",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "skew": 3,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-snapshot-2'

    def test_delete_globalaccelerator_snapshot(self):
        session_factory = self.replay_flight_data("test_delete_globalaccelerator_snapshot")
        p = self.load_policy(
            {
                "name": "delete-globalaccelerator-snapshot",
                "resource": "globalaccelerator-snapshot",
                "filters": [{"tag:owner": "policy"}],
                "actions": [{
                                "type": "delete",
                            }],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual(resources[0]["Name"], "test-snapshot-2")

    def test_globalaccelerator_user_tag_untag(self):
        session_factory = self.replay_flight_data('test_globalaccelerator_user_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'globalaccelerator-tag-untag',
                'resource': 'globalaccelerator-user',
                'filters': [{
                    'tag:owner': 'policy'
                }],
                'actions': [{
                    'type': 'tag',
                    'tags': tag
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        time.sleep(60)
        p = self.load_policy(
            {
                'name': 'globalaccelerator-tag-untag',
                'resource': 'globalaccelerator-user',
                'filters': [{
                    'tag:owner': 'policy'
                }],
                'actions': [
                {
                    'type': 'remove-tag',
                    'tags': ['owner']
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        time.sleep(60)
        client = session_factory().client("globalaccelerator")
        tags = client.list_tags(ResourceArn=resources[0]["ARN"])["TagList"]
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_globalaccelerator_user_mark_for_op(self):
        session_factory = self.replay_flight_data("test_globalaccelerator_user_mark_for_op")
        p = self.load_policy(
            {
                "name": "globalaccelerator-user-mark",
                "resource": "globalaccelerator-user",
                "filters": [
                    {'tag:owner': 'policy'},
                ],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "days": 1,
                    }
                ],
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        time.sleep(30)
        p = self.load_policy(
            {
                "name": "globalaccelerator-marked",
                "resource": "globalaccelerator-user",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "skew": 3,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-user'

    def test_delete_globalaccelerator_user(self):
        session_factory = self.replay_flight_data("test_delete_globalaccelerator_user")
        p = self.load_policy(
            {
                "name": "delete-globalaccelerator-user",
                "resource": "globalaccelerator-user",
                "filters": [{"tag:owner": "policy"}],
                "actions": [{
                                "type": "delete",
                            }],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual(resources[0]["Name"], "test-user")

    def test_globalaccelerator_acl_tag_untag(self):
        session_factory = self.replay_flight_data('test_globalaccelerator_acl_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'globalaccelerator-tag-untag',
                'resource': 'globalaccelerator-acl',
                'filters': [{
                    'tag:owner': 'policy'
                }],
                'actions': [{
                    'type': 'tag',
                    'tags': tag
                },
                {
                    'type': 'remove-tag',
                    'tags': ['owner']
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        client = session_factory().client("globalaccelerator")
        tags = client.list_tags(ResourceArn=resources[0]["ARN"])["TagList"]
        self.assertEqual(1, len(tags))
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_globalaccelerator_acl_mark_for_op(self):
        session_factory = self.replay_flight_data("test_globalaccelerator_acl_mark_for_op")
        p = self.load_policy(
            {
                "name": "globalaccelerator-snapshot-mark",
                "resource": "globalaccelerator-acl",
                "filters": [
                    {'tag:owner': 'policy'},
                ],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "days": 1,
                    }
                ],
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        p = self.load_policy(
            {
                "name": "globalaccelerator-marked",
                "resource": "globalaccelerator-acl",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "skew": 3,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'open-access'

    def test_delete_globalaccelerator_acl(self):
        session_factory = self.replay_flight_data("test_delete_globalaccelerator_acl")
        p = self.load_policy(
            {
                "name": "delete-globalaccelerator-acl",
                "resource": "globalaccelerator-acl",
                "filters": [{"tag:team": "test"}],
                "actions": [{
                                "type": "delete",
                            }],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual(resources[0]["Name"], "test-acl")
