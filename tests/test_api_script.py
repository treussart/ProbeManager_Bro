""" venv/bin/python probemanager/manage.py test bro.tests.test_api_script --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from bro.models import ScriptBro


class APITestScript(APITestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature',
                'test-bro-script', 'test-bro-ruleset', 'test-bro-conf',
                'test-bro-bro', 'test-bro-critical-stack']

    def setUp(self):
        self.client = APIClient()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

    def test_script(self):
        response = self.client.get('/api/v1/bro/script/102/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        with open(settings.BASE_DIR + '/bro/tests/data/test-script-notmatch.bro', encoding='UTF_8') as s:
            response = self.client.post('/api/v1/bro/script/', {
                'rev': '1',
                'rule_full': str(s.read().replace('\r', '')),
                'name': 'Heartbeat',
                'enabled': True
            })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(ScriptBro.get_by_name('Heartbeat'))
        response = self.client.get('/api/v1/bro/script/' + str(ScriptBro.get_by_name('Heartbeat').id) + '/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        response = self.client.post('/api/v1/bro/script/', {
            "rev": 0,
            "reference": "string",
            "rule_full": "string pouet pouet",
            "enabled": True,
            "name": "string",
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        with open(settings.BASE_DIR + '/bro/tests/data/test-script-match.bro', encoding='UTF_8') as s:
            response = self.client.put('/api/v1/bro/script/102/', {
                'rev': '0',
                'rule_full': str(s.read().replace('\r', '')),
                'name': 'Heartbeat message smaller than minimum required length',
            })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.put('/api/v1/bro/script/102/', {
            "rev": 1
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.put('/api/v1/bro/script/102/', {
            'rev': '0',
            'rule_full': "Pouete pouet prout",
            'name': 'Failed',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.patch('/api/v1/bro/script/102/', {
            "rev": 1
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.patch('/api/v1/bro/script/102/', {
            "rev": "test"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.patch('/api/v1/bro/script/102/', {
            "rule_full": "test pouet pouet prout t"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
