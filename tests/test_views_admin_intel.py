""" venv/bin/python probemanager/manage.py test bro.tests.test_views_admin_intel --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.db import transaction
from django.test import Client, TestCase
from django.utils import timezone

from bro.models import Intel


class ViewsConfAdminTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature',
                'test-bro-script', 'test-bro-ruleset', 'test-bro-conf',
                'test-bro-bro', 'test-bro-intel']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))
        self.date_now = timezone.now()

    def tearDown(self):
        self.client.logout()

    def test_intel(self):
        response = self.client.get('/admin/bro/intel/', follow=True)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(len(Intel.get_all()), 2)
        response = self.client.post('/admin/bro/intel/add/', {"value": "192.168.50.111",
                                                              "indicator": "Intel::ADDR",
                                                              "indicator_type": "-",
                                                              "meta_source": "-",
                                                              "meta_desc": "-",
                                                              "meta_url": "-"
                                                              },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully.', str(response.content))
        self.assertEqual(len(Intel.get_all()), 3)
        response = self.client.post('/admin/bro/intel/add/', {"value": "192.168.50.111",
                                                              "indicator": "Intel::ADDR",
                                                              "indicator_type": "-",
                                                              "meta_source": "-",
                                                              "meta_desc": "-",
                                                              "meta_url": "-"
                                                              },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Intel with this Value and Indicator already exists.', str(response.content))
        self.assertEqual(len(Intel.get_all()), 3)

        response = self.client.get('/admin/bro/intel/import_csv/', follow=True)
        self.assertEqual(response.status_code, 200)
        with open(settings.BASE_DIR + '/bro/tests/data/test-intel.csv', encoding='utf_8') as f:
            response = self.client.post('/admin/bro/intel/import_csv/', {'file': f},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('CSV file imported successfully !', str(response.content))
        with transaction.atomic():
            with open(settings.BASE_DIR + '/bro/tests/data/test-intel.csv', encoding='utf_8') as f:
                response = self.client.post('/admin/bro/intel/import_csv/', {'file': f},
                                            follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn('Error during the import : duplicate key value violates unique constraint',
                          str(response.content))
