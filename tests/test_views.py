""" venv/bin/python probemanager/manage.py test bro.tests.test_views --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase

from bro.models import Bro


class ViewsBroTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature',
                'test-bro-script', 'test-bro-ruleset', 'test-bro-conf', 'test-bro-bro']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def test_home(self):
        """
        Home Page who list instances of Bro
        """
        response = self.client.get('/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Home</title>', str(response.content))
        self.assertEqual('core/index.html', response.templates[0].name)
        self.assertIn('core', response.resolver_match.app_names)
        self.assertIn('function index', str(response.resolver_match.func))
        with self.assertTemplateUsed('bro/home.html'):
            self.client.get('/', follow=True)

    def test_index(self):
        """
         Index Page for an instance of Bro
        """
        bro = Bro.get_by_id(101)
        response = self.client.get('/bro/' + str(bro.id))
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Bro</title>', str(response.content))
        self.assertEqual('bro/index.html', response.templates[0].name)
        self.assertIn('bro', response.resolver_match.app_names)
        self.assertIn('function probe_index', str(response.resolver_match.func))
        self.assertEqual(str(response.context['user']), 'testuser')
        with self.assertTemplateUsed('bro/index.html'):
            self.client.get('/bro/' + str(bro.id))
        response = self.client.get('/bro/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/stop/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe stopped successfully', str(response.content))
        response = self.client.get('/bro/stop/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/start/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe started successfully', str(response.content))
        response = self.client.get('/bro/start/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/status/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('get status successfully', str(response.content))
        response = self.client.get('/bro/status/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/restart/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe restarted successfully', str(response.content))
        response = self.client.get('/bro/restart/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/reload/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Probe reloaded successfully', str(response.content))
        response = self.client.get('/bro/reload/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/deploy-conf/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test configuration OK', str(response.content))
        self.assertIn('Deployed configuration successfully', str(response.content))
        response = self.client.get('/bro/deploy-conf/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/deploy-rules/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Deployed rules launched with succeed', str(response.content))
        response = self.client.get('/bro/deploy-rules/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/update/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/bro/update/99')
        self.assertEqual(response.status_code, 404)

        response = self.client.get('/bro/install/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/bro/install/99')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/bro/update/' + str(bro.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('launched with succeed', str(response.content))
        response = self.client.get('/bro/update/99')
        self.assertEqual(response.status_code, 404)

    def test_admin_index(self):
        # index
        response = self.client.get('/admin/bro/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Bro administration', str(response.content))
