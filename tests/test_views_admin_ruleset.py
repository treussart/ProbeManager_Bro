""" venv/bin/python probemanager/manage.py test bro.tests.test_views_admin_ruleset --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from bro.models import SignatureBro, RuleSetBro, ScriptBro


class ViewsRuleSetAdminTest(TestCase):
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

    def test_rule_set(self):
        response = self.client.get('/admin/bro/rulesetbro/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/bro/rulesetbro/', {'action': 'test_rules',
                                                                         '_selected_action': '101'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test rules OK', str(response.content))
        # test fail test signature
        self.assertEqual(len(SignatureBro.get_all()), 1)
        response = self.client.post('/admin/bro/signaturebro/add/', {'rev': '0',
                                                                     'rule_full': 'signature my-first-sig {ip-proto == prout \n dst-port == 80p \n plad /.*root/ \n event "Found root!"}',
                                                                     'sid': '668',
                                                                     'msg': 'fail test',
                                                                     },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully', str(response.content))
        self.assertIn('Test signature failed', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 2)
        response = self.client.post('/admin/bro/scriptbro/add/', {'rev': '0',
                                                                  'rule_full': '1',
                                                                  'name': 'fail script test',
                                                                  },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully', str(response.content))
        self.assertIn('Test script failed', str(response.content))

        self.assertEqual(len(RuleSetBro.get_all()), 1)
        response = self.client.post('/admin/bro/rulesetbro/add/', {'name': 'test_signatures',
                                                                   'description': 'test fail',
                                                                   'signatures': str(SignatureBro.get_by_msg('fail test').id),
                                                                   'scripts': ScriptBro.get_by_name('fail script test').id
                                                                   },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(RuleSetBro.get_all()), 2)
        response = self.client.post('/admin/bro/rulesetbro/', {'action': 'test_rules',
                                                                         '_selected_action': RuleSetBro.get_by_name('test_signatures').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test rules failed !', str(response.content))
        response = self.client.post('/admin/bro/rulesetbro/', {'action': 'delete_selected',
                                                                         '_selected_action': RuleSetBro.get_by_name('test_signatures').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/bro/rulesetbro/', {'action': 'delete_selected',
                                                                         '_selected_action': RuleSetBro.get_by_name('test_signatures').id,
                                                                         'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(RuleSetBro.get_all()), 1)

