# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest

class MemoryDbTest(BaseTest):

    def test_memorydb(self):
        factory = self.replay_flight_data("test_memory_db")
        p = self.load_policy({
            'name': 'memorydb',
            'resource': 'aws.memorydb'},
            session_factory=factory,
            config={'region': 'us-east-1'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['Name'] == 'test-cluster'

    def test_memorydb_tag_untag(self):
        session_factory = self.replay_flight_data('test_memorydb_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'memorydb-tag-untag',
                'resource': 'memorydb',
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
        client = session_factory().client("memorydb")
        tags = client.list_tags(ResourceArn=resources[0]["ARN"])["TagList"]
        self.assertEqual(1, len(tags))
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_memorydb_mark_for_op(self):
        session_factory = self.replay_flight_data("test_memorydb_mark_for_op")
        p = self.load_policy(
            {
                "name": "memorydb-mark",
                "resource": "memorydb",
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
                "name": "memorydb-marked",
                "resource": "memorydb",
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
        assert resources[0]['Name'] == 'test-cluster'


    def test_delete_memorydb(self):
        session_factory = self.replay_flight_data("test_delete_memorydb")
        p = self.load_policy(
            {
                "name": "delete-memorydb",
                "resource": "memorydb",
                "filters": [{"tag:owner": "policy"}],
                "actions": [{
                                "type": "delete",
                            }],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual(resources[0]["Name"], "test-cluster")
