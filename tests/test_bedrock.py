# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest


class BedrockCustomModel(BaseTest):

    def test_bedrock_custom_model(self):
        session_factory = self.replay_flight_data('test_bedrock_custom_model')
        p = self.load_policy(
            {
                'name': 'bedrock-custom-model-tag',
                'resource': 'bedrock-custom-model',
                'filters': [
                    {'tag:foo': 'absent'},
                    {'tag:Owner': 'c7n'},
                ],
                'actions': [
                    {
                        'type': 'tag',
                        'tags': {'foo': 'bar'}
                    },
                    {
                        'type': 'remove-tag',
                        'tags': ['Owner']
                    }
                ]
            }, session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('bedrock')
        tags = client.list_tags_for_resource(resourceARN=resources[0]['modelArn'])['tags']
        self.assertEqual(len(tags), 1)
        self.assertEqual(tags, [{'key': 'foo', 'value': 'bar'}])

    def test_bedrock_custom_model_delete(self):
        session_factory = self.replay_flight_data('test_bedrock_custom_model_delete')
        p = self.load_policy(
            {
                'name': 'custom-model-delete',
                'resource': 'bedrock-custom-model',
                'filters': [{'modelName': 'c7n-test3'}],
                'actions': [{'type': 'delete'}]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('bedrock')
        models = client.list_custom_models().get('modelSummaries')
        self.assertEqual(len(models), 0)


class BedrockKnowledgeBase(BaseTest):

    def test_bedrock_knowledge_base(self):
        session_factory = self.replay_flight_data('test_bedrock_knowledge_base')
        p = self.load_policy(
            {
                "name": "bedrock-knowledge-base-test",
                "resource": "bedrock-knowledge-base",
                "filters": [
                    {"tag:resource": "absent"},
                    {"tag:owner": "policy"},
                ],
                "actions": [
                   {
                        "type": "tag",
                        "tags": {"resource": "knowledge"}
                   },
                   {
                        "type": "remove-tag",
                        "tags": ["owner"]
                   }
                ]
            }, session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('bedrock-agent')
        tags = client.list_tags_for_resource(resourceArn=resources[0]['knowledgeBaseArn'])['tags']
        self.assertEqual(len(tags), 1)
        self.assertEqual(tags, {'resource': 'knowledge'})

    def test_bedrock_knowledge_base_delete(self):
        session_factory = self.replay_flight_data('test_bedrock_knowledge_base_delete')
        p = self.load_policy(
            {
                "name": "knowledge-base-delete",
                "resource": "bedrock-knowledge-base",
                "filters": [{"tag:resource": "knowledge"}],
                "actions": [{"type": "delete"}]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('bedrock-agent')
        knowledgebases = client.list_knowledge_bases().get('knowledgeBaseSummaries')
        self.assertEqual(len(knowledgebases), 0)
