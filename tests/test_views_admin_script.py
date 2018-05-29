""" venv/bin/python probemanager/manage.py test bro.tests.test_views_admin_script --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from bro.models import ScriptBro, RuleSetBro


class ViewsScriptAdminTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature',
                'test-bro-script', 'test-bro-ruleset', 'test-bro-conf',
                'test-bro-bro']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))
        self.date_now = timezone.now()

    def tearDown(self):
        self.client.logout()

    def test_script(self):
        self.assertEqual(len(ScriptBro.get_all()), 1)
        response = self.client.get('/admin/bro/scriptbro/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/bro/scriptbro/', {'action': 'make_enabled',
                                                              '_selected_action': str(ScriptBro.get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 rule was successfully marked as enabled", str(response.content))
        response = self.client.post('/admin/bro/scriptbro/', {'action': 'make_disabled',
                                                              '_selected_action': str(ScriptBro.get_all()[0].id)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 rule was successfully marked as disabled", str(response.content))

        response = self.client.post('/admin/bro/scriptbro/add/', {'rev': '0',
                                                                  'rule_full': '1',
                                                                  'name': 'fail script test',
                                                                  },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test script failed', str(response.content))
        self.assertEqual(len(ScriptBro.get_all()), 1)
        response = self.client.post('/admin/bro/scriptbro/', {'action': 'make_enabled',
                                                              '_selected_action': [ScriptBro.
                                                                                   get_all()[0].id, ]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 rule was successfully marked as enabled", str(response.content))
        self.assertTrue(ScriptBro.get_by_name('The hash value of a file transferred over HTTP matched').enabled)
        response = self.client.post('/admin/bro/scriptbro/', {'action': 'make_disabled',
                                                              '_selected_action': [ScriptBro.
                                                                                   get_all()[0].id, ]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("1 rule was successfully marked as disabled", str(response.content))
        self.assertFalse(ScriptBro.get_by_name('The hash value of a file transferred over HTTP matched').enabled)

        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'test',
                                     '_selected_action': ScriptBro.get_by_name('The hash value of a file '
                                                                               'transferred over HTTP matched').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test OK', str(response.content))

        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': ScriptBro.get_by_name('The hash value of a file '
                                                                               'transferred over HTTP matched').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': ScriptBro.get_by_name('The hash value of a file '
                                                                               'transferred over HTTP matched').id,
                                     'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(ScriptBro.get_all()), 0)

        with open(settings.BASE_DIR + '/bro/tests/data/test-script.pcap', 'rb') as f:
            with open(settings.BASE_DIR + '/bro/tests/data/test-script-match.bro', encoding='UTF_8') as s:
                response = self.client.post('/admin/bro/scriptbro/add/', {'rev': '1',
                                                                          'rule_full': str(s.read().replace('\r', '')),
                                                                          'name': 'failed logins',
                                                                          'file_test_success': f,
                                                                          },
                                            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test script OK', str(response.content))
        self.assertEqual(len(ScriptBro.get_all()), 1)
        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'test',
                                     '_selected_action': ScriptBro.get_by_name('failed logins').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test OK', str(response.content))
        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': ScriptBro.get_by_name('failed logins').id,
                                     'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(ScriptBro.get_all()), 0)
        with open(settings.BASE_DIR + '/bro/tests/data/test-script.pcap', 'rb') as f:
            with open(settings.BASE_DIR + '/bro/tests/data/test-script-notmatch.bro', encoding='UTF_8') as s:
                response = self.client.post('/admin/bro/scriptbro/add/', {'rev': '1',
                                                                          'rule_full': str(
                                                                                 s.read().replace('\r', '')),
                                                                          'name': 'failed logins',
                                                                          'file_test_success': f,
                                                                          },
                                            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test script failed !', str(response.content))
        self.assertEqual(len(ScriptBro.get_all()), 1)
        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'test',
                                     '_selected_action': ScriptBro.get_by_name('failed logins').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test failed', str(response.content))

        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'add_ruleset',
                                     '_selected_action': ScriptBro.get_by_name('failed logins').id,
                                     'ruleset': RuleSetBro.get_by_name('test_bro_ruleset').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(ScriptBro.get_by_name('failed logins'), RuleSetBro.get_by_name('test_bro_ruleset').scripts.all())
        response = self.client.post('/admin/bro/scriptbro/',
                                    {'action': 'remove_ruleset',
                                     '_selected_action': ScriptBro.get_by_name('failed logins').id,
                                     'ruleset': RuleSetBro.get_by_name('test_bro_ruleset').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(ScriptBro.get_by_name('failed logins'),
                         RuleSetBro.get_by_name('test_bro_ruleset').scripts.all())
