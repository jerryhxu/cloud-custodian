# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest


class NetworkFirewallTest(BaseTest):

    def test_firewall(self):
        factory = self.replay_flight_data("test_network_firewall")
        p = self.load_policy({
            'name': 'firewall-get',
            'resource': 'aws.firewall'},
            session_factory=factory,
            config={'region': 'us-east-2'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['FirewallName'] == 'unicron'

    def test_firewall_config(self):
        factory = self.replay_flight_data('test_network_firewall_config')
        p = self.load_policy({
            'name': 'firewall-config',
            'source': 'config',
            'resource': 'aws.firewall'},
            session_factory=factory,
            config={'region': 'us-east-2'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['FirewallName'] == 'unicron'

    def test_firewall_tag_untag(self):
        session_factory = self.replay_flight_data('test_firewall_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'firewall-tag-untag',
                'resource': 'firewall',
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
        client = session_factory().client("network-firewall")
        firewall = client.describe_firewall(FirewallName=resources[0]['FirewallName'])
        tags = firewall['Firewall'].get('Tags')
        self.assertEqual(1, len(tags))
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_firewall_mark_for_op(self):
        session_factory = self.replay_flight_data("test_firewall_mark_for_op")
        p = self.load_policy(
            {
                "name": "firewall-mark",
                "resource": "firewall",
                "filters": [
                    {"tag:owner": "policy"},
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
                "name": "firewall-marked",
                "resource": "firewall",
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

    def test_firewall_logging(self):
        factory = self.record_flight_data('test_network_firewall_logging')
        p = self.load_policy(
            {
                "name": "firewall-config",
                "resource": "aws.firewall",
                "filters": [
                        {
                            "type": "logging",
                            "attrs": [
                            {"LogType": "ALERT"},
                            ]
                        }
                    ],
                },
            session_factory = factory,
            config = {'region': 'us-east-1'}
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['FirewallName'] == 'test-firewall'

    def test_delete_firewall(self):
        session_factory = self.record_flight_data("test_delete_firewall")
        p = self.load_policy(
            {
                "name": "delete-firewall",
                "resource": "firewall",
                "filters": [{"tag:owner": "policy"}],
                "actions": [{"type": "delete"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(resources[0]["FirewallName"], "test-firewall")

    # def test_force_delete_dynamodb_tables(self):
    #     session_factory = self.replay_flight_data("test_force_delete_dynamodb_tables")
    #     client = session_factory().client("dynamodb")
    #     self.patch(DeleteTable, "executor_factory", MainThreadExecutor)
    #     p = self.load_policy(
    #         {
    #             "name": "delete-empty-tables",
    #             "resource": "dynamodb-table",
    #             "filters": [{"TableName": "c7n-test"}],
    #             "actions": [
    #                 {
    #                     "type": "delete",
    #                     "force": True
    #                 }
    #             ],
    #         },
    #         session_factory=session_factory,
    #     )
    #     resources = p.run()
    #     self.assertEqual(resources[0]["DeletionProtectionEnabled"], True)
    #     table = client.describe_table(TableName="c7n-test")["Table"]
    #     self.assertEqual(table.get('TableStatus'), 'DELETING')

    # def test_update_tables(self):
    #     session_factory = self.replay_flight_data("test_dynamodb_update_table")
    #     client = session_factory().client("dynamodb")
    #     p = self.load_policy(
    #         {
    #             "name": "update-empty-tables",
    #             "resource": "dynamodb-table",
    #             "actions": [{"type": "update", "BillingMode": "PAY_PER_REQUEST"}],
    #         },
    #         session_factory=session_factory,
    #     )
    #     resources = p.run()
    #     assert resources[0]["TableName"] == "cc-testing-table"
    #     t = client.describe_table(TableName="cc-testing-table")["Table"]
    #     assert t["BillingModeSummary"]["BillingMode"] == "PAY_PER_REQUEST"
