""" venv/bin/python probemanager/manage.py test bro.tests.test_views_admin_critical_stack --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from bro.models import CriticalStack, Bro


class ViewsCriticalStackAdminTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature',
                'test-bro-script', 'test-bro-ruleset', 'test-bro-conf',
                'test-bro-bro', 'test-bro-critical-stack']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))
        self.date_now = timezone.now()

    def tearDown(self):
        self.client.logout()

    def test_critical_stack(self):
        response = self.client.get('/admin/bro/criticalstack/', follow=True)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(len(CriticalStack.objects.all()), 1)
        response = self.client.post('/admin/bro/criticalstack/add/', {
            "api_key": "19216850111",
            "scheduled_pull": "1",
            "bro": "101",
            },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully.', str(response.content))
        self.assertEqual(len(CriticalStack.objects.all()), 2)
        self.assertEqual("19216850111_deploy_critical_stack",
                         PeriodicTask.objects.get(name="19216850111_deploy_critical_stack").name)

        response = self.client.post('/admin/bro/criticalstack/add/', {
            "api_key": "19216850111",
            "scheduled_pull": "1",
            "bro": "101",
            },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Critical stack with this Api key already exists.', str(response.content))
        self.assertEqual(len(CriticalStack.objects.all()), 2)

        response = self.client.get('/admin/bro/criticalstack/2/delete/',
                                   follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure ', str(response.content))
        response = self.client.post('/admin/bro/criticalstack/2/delete/',
                                    {'post': 'yes'}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("was deleted successfully.", str(response.content))
        self.assertEqual(len(CriticalStack.objects.all()), 1)

        with self.assertRaises(Exception):
            PeriodicTask.objects.get(name="19216850111_deploy_critical_stack")
