""" venv/bin/python probemanager/manage.py test bro.tests.test_tasks --settings=probemanager.settings.dev """
from django.conf import settings
from django.test import TestCase

from bro.models import CriticalStack
from bro.tasks import deploy_critical_stack


class TasksBroTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature',
                'test-bro-script', 'test-bro-ruleset', 'test-bro-conf',
                'test-bro-bro', 'test-bro-critical-stack']

    @classmethod
    def setUpTestData(cls):
        settings.CELERY_TASK_ALWAYS_EAGER = True

    def test_deploy_critical_stack(self):
        critical_stack = CriticalStack.objects.get(id=1)
        response = deploy_critical_stack.delay(critical_stack.api_key)
        self.assertIn('deployed successfully', response.get()['message'])
        self.assertTrue(response.successful())
