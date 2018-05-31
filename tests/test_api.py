""" venv/bin/python probemanager/manage.py test bro.tests.test_api --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from bro.models import Bro, CriticalStack


class APITest(APITestCase):
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

    def test_conf(self):
        response = self.client.get('/api/v1/bro/configuration/101/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_bro(self):
        response = self.client.get('/api/v1/bro/bro/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        data = {'name': 'test',
                'secure_deployment': True,
                'scheduled_rules_deployment_enabled': True,
                'scheduled_rules_deployment_crontab': 4,
                'scheduled_check_enabled': True,
                'scheduled_check_crontab': 3,
                'server': 1,
                'rulesets': [101, ],
                'configuration': 101,
                'installed': True}

        data_put = {'name': 'test',
                    'secure_deployment': True,
                    'server': 1,
                    'rulesets': [101, ],
                    'configuration': 101,
                    'installed': False}

        data_patch = {'installed': True}

        response = self.client.post('/api/v1/bro/bro/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post('/api/v1/bro/bro/', {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/bro/bro/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)

        self.assertTrue(PeriodicTask.objects.get(name="test_deploy_rules_" + str(CrontabSchedule.objects.get(id=4))))
        self.assertTrue(PeriodicTask.objects.get(name="test_check_task"))

        response = self.client.put('/api/v1/bro/bro/' + str(Bro.get_by_name('test').id) + '/', data_put)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Bro.get_by_name('test').installed)

        response = self.client.put('/api/v1/bro/bro/' + str(Bro.get_by_name('test').id) + '/', {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch('/api/v1/bro/bro/' + str(Bro.get_by_name('test').id) + '/', {'configuration': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch('/api/v1/bro/bro/' + str(Bro.get_by_name('test').id) + '/', data_patch)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Bro.get_by_name('test').installed)

        response = self.client.patch('/api/v1/bro/bro/' + str(Bro.get_by_name('test').id) + '/',
                                     {'scheduled_rules_deployment_enabled': False})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Bro.get_by_name('test').scheduled_rules_deployment_enabled)

        response = self.client.delete('/api/v1/bro/bro/' + str(Bro.get_by_name('test').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get('/api/v1/bro/bro/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_deploy_rules_" + str(CrontabSchedule.objects.get(id=4)))
        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_check_task")

        response = self.client.get('/api/v1/bro/bro/101/test_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/start/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/stop/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/restart/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/reload/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/status/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/uptime/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['uptime'])

        response = self.client.get('/api/v1/bro/bro/101/deploy_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/bro/101/deploy_conf/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        # response = self.client.get('/api/v1/bro/bro/101/install/')
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(response.data['status'])
        #
        # response = self.client.get('/api/v1/bro/bro/101/install/?version=' + settings.BRO_VERSION)
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(response.data['status'])

    def test_signature(self):
        response = self.client.get('/api/v1/bro/signature/101/test/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_ruleset(self):
        response = self.client.get('/api/v1/bro/ruleset/101/test_rules/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

    def test_criticalstack(self):
        response = self.client.get('/api/v1/bro/criticalstack/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        data = {'api_key': '19216850111',
                'scheduled_pull': 1,
                'bros': [101, ]}

        response = self.client.post('/api/v1/bro/criticalstack/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        criticalstack = CriticalStack.objects.get(api_key="19216850111")
        self.assertTrue(PeriodicTask.objects.get(name=str(criticalstack) + "_deploy_critical_stack"))

        response = self.client.post('/api/v1/bro/criticalstack/', {'api_key': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/bro/criticalstack/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)

        response = self.client.delete('/api/v1/bro/criticalstack/' + str(criticalstack.id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name=str(criticalstack) + "_deploy_critical_stack")

        response = self.client.get('/api/v1/bro/criticalstack/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        response = self.client.get('/api/v1/bro/criticalstack/1/pull/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.get('/api/v1/bro/criticalstack/1/list_feeds/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        self.assertIn('test', response.data['message'])
