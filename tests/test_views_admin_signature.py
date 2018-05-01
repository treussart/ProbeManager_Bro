""" venv/bin/python probemanager/manage.py test bro.tests.test_views_admin_signature --settings=probemanager.settings.dev """
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.utils import timezone

from bro.models import SignatureBro, RuleSetBro


class ViewsSignatureAdminTest(TestCase):
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

    def test_signature(self):
        self.assertEqual(len(SignatureBro.get_all()), 1)
        response = self.client.get('/admin/bro/signaturebro/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(SignatureBro.get_by_msg('Found root!').enabled)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'make_disabled',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as disabled", str(response.content))
        self.assertFalse(SignatureBro.get_by_msg('Found root!').enabled)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'make_enabled',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("successfully marked as enabled", str(response.content))
        self.assertTrue(SignatureBro.get_by_msg('Found root!').enabled)

        response = self.client.post('/admin/bro/signaturebro/add/', {'rev': '0',
                                                                     'rule_full': '1',
                                                                     'sid': '666',
                                                                     'msg': 'fail test',
                                                                     },
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('was added successfully', str(response.content))
        self.assertIn('Test signature failed !', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 2)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'make_disabled',
                                     '_selected_action': [SignatureBro.get_by_msg('Found root!').id,
                                                          SignatureBro.get_by_msg('fail test').id]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 rules were successfully marked as disabled", str(response.content))
        self.assertFalse(SignatureBro.get_by_msg('Found root!').enabled)
        self.assertFalse(SignatureBro.get_by_msg('fail test').enabled)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'make_enabled',
                                     '_selected_action': [SignatureBro.get_by_msg('Found root!').id,
                                                          SignatureBro.get_by_msg('fail test').id]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 rules were successfully marked as enabled", str(response.content))
        self.assertTrue(SignatureBro.get_by_msg('Found root!').enabled)
        self.assertTrue(SignatureBro.get_by_msg('fail test').enabled)

        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'test',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test OK', str(response.content))
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'test',
                                     '_selected_action': SignatureBro.get_by_msg('fail test').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test failed !', str(response.content))

        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'add_ruleset',
                                     '_selected_action': SignatureBro.get_by_msg('fail test').id,
                                     'ruleset': RuleSetBro.get_by_name('test_bro_ruleset').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(SignatureBro.get_by_msg('fail test'), RuleSetBro.get_by_name('test_bro_ruleset').signatures.all())
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'remove_ruleset',
                                     '_selected_action': SignatureBro.get_by_msg('fail test').id,
                                     'ruleset': RuleSetBro.get_by_name('test_bro_ruleset').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SignatureBro.get_by_msg('fail test'),
                         RuleSetBro.get_by_name('test_bro_ruleset').signatures.all())

        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': SignatureBro.get_by_msg('fail test').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Are you sure you want to delete the selected ', str(response.content))
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': SignatureBro.get_by_msg('fail test').id,
                                     'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 1)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id,
                                     'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 0)
        with open(settings.BASE_DIR + '/bro/tests/data/test-signature.pcap', 'rb') as f:
            with open(settings.BASE_DIR + '/bro/tests/data/test-signature-match.sig', 'r') as s:
                response = self.client.post('/admin/bro/signaturebro/add/',
                                            {'rev': '1',
                                             'rule_full': str(s.read().replace('\r', '')),
                                             'sid': '767',
                                             'msg': 'Found root!',
                                             'file_test_success': f,
                                             },
                                            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signature OK', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 1)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'test',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test OK', str(response.content))
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'delete_selected',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id,
                                     'post': 'yes'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Successfully deleted 1 ', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 0)
        with open(settings.BASE_DIR + '/bro/tests/data/test-signature.pcap', 'rb') as f:
            with open(settings.BASE_DIR + '/bro/tests/data/test-signature-error.sig', 'r') as s:
                response = self.client.post('/admin/bro/signaturebro/add/',
                                            {'rev': '1',
                                             'rule_full': str(s.read().replace('\r', '')),
                                             'sid': '768',
                                             'msg': 'Found root!',
                                             'file_test_success': f,
                                             }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test signature failed !', str(response.content))
        self.assertEqual(len(SignatureBro.get_all()), 1)
        response = self.client.post('/admin/bro/signaturebro/',
                                    {'action': 'test',
                                     '_selected_action': SignatureBro.get_by_msg('Found root!').id},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test failed !', str(response.content))
