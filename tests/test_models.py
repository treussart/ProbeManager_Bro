""" venv/bin/python probemanager/manage.py test bro.tests.test_models --settings=probemanager.settings.dev """
from django.conf import settings
from django.db import transaction
from django.db.utils import IntegrityError
from django.test import TestCase
from django.utils import timezone

from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro, Intel, CriticalStack


class ConfigurationTest(TestCase):
    fixtures = ['init', 'crontab', 'test-bro-conf']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_conf_bro(self):
        all_conf_bro = Configuration.get_all()
        conf_bro = Configuration.get_by_id(101)
        self.assertEqual(len(all_conf_bro), 1)
        self.assertEqual(conf_bro.name, "test_bro_conf")
        self.assertEqual(conf_bro.my_scripts, "/usr/local/bro/share/bro/site/myscripts.bro")
        self.assertEqual(conf_bro.bin_directory, "/usr/local/bro/bin/")
        self.assertEqual(str(conf_bro), "test_bro_conf")
        conf_bro = Configuration.get_by_id(199)
        self.assertEqual(conf_bro, None)
        with self.assertRaises(IntegrityError):
            Configuration.objects.create(name="test_bro_conf")


class RuleSetBroTest(TestCase):
    fixtures = ['init', 'crontab', 'test-bro-signature', 'test-bro-script', 'test-bro-ruleset']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_ruleset_bro(self):
        all_ruleset_bro = RuleSetBro.get_all()
        ruleset_bro = RuleSetBro.get_by_id(101)
        self.assertEqual(len(all_ruleset_bro), 1)
        self.assertEqual(ruleset_bro.name, "test_bro_ruleset")
        self.assertEqual(ruleset_bro.description, "")
        self.assertEqual(str(ruleset_bro), "test_bro_ruleset")
        ruleset_bro = RuleSetBro.get_by_id(199)
        self.assertEqual(ruleset_bro, None)
        with self.assertRaises(IntegrityError):
            RuleSetBro.objects.create(name="test_bro_ruleset",
                                      description="",
                                      created_date=self.date_now
                                      )


class ScriptBroTest(TestCase):
    fixtures = ['init', 'crontab', 'test-bro-script']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_script_bro(self):
        all_script_bro = ScriptBro.get_all()
        script_bro = ScriptBro.get_by_id(102)
        self.assertEqual(len(all_script_bro), 1)
        self.assertEqual(script_bro.name, "The hash value of a file transferred over HTTP matched")
        self.assertEqual(script_bro.rev, 0)
        self.assertEqual(script_bro.reference, None)
        self.assertTrue(script_bro.enabled)
        script_bros = ScriptBro.find("FTP brute-forcing detector")
        self.assertEqual(script_bros[0].name, "The hash value of a file transferred over HTTP matched")
        self.assertEqual(str(script_bro), "The hash value of a file transferred over HTTP matched")
        script_bro = ScriptBro.get_by_id(199)
        self.assertEqual(script_bro, None)
        self.assertEqual(ScriptBro.get_by_name("101"), None)
        with self.assertRaises(IntegrityError):
            with open(settings.BASE_DIR + '/bro/tests/data/test-script-notmatch.bro', encoding='utf_8') as f:
                ScriptBro.objects.create(name="The hash value of a file transferred over HTTP matched",
                                         rev=0,
                                         reference="",
                                         rule_full=f.read(),
                                         enabled=True,
                                         created_date=self.date_now
                                         )


class SignatureBroTest(TestCase):
    fixtures = ['init', 'crontab', 'test-bro-signature']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_signature_bro(self):
        all_signature_bro = SignatureBro.get_all()
        signature_bro = SignatureBro.get_by_id(101)
        signature_bros = SignatureBro.find("Found root!")
        self.assertEqual(len(all_signature_bro), 1)
        self.assertEqual(signature_bro.rev, 0)
        self.assertEqual(signature_bro.msg, "Found root!")
        self.assertEqual(signature_bro.reference, None)
        self.assertTrue(signature_bro.enabled)
        self.assertEqual(signature_bros[0].msg, "Found root!")
        self.assertEqual(str(signature_bro), "101 : Found root!")
        signature_bro = SignatureBro.get_by_id(199)
        self.assertEqual(signature_bro, None)
        self.assertEqual(SignatureBro.get_by_msg("101"), None)


class BroTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature', 'test-bro-script', 'test-bro-ruleset',
                'test-bro-conf', 'test-bro-bro']

    @classmethod
    def setUpTestData(cls):
        cls.date_now = timezone.now()

    def test_bro(self):
        all_bro = Bro.get_all()
        bro = Bro.get_by_id(101)
        self.assertEqual(len(all_bro), 1)
        self.assertEqual(bro.name, "test_instance_bro")
        self.assertEqual(str(bro), "test_instance_bro : ")
        bro = Bro.get_by_id(199)
        self.assertEqual(bro, None)
        with self.assertRaises(IntegrityError):
            Bro.objects.create(name="test_instance_bro")

    def test_test(self):
        bro = Bro.get_by_id(101)
        response = bro.server.test()
        self.assertTrue(response)
        response = bro.server.test_become()
        self.assertTrue(response)

    def test_running(self):
        bro = Bro.get_by_id(101)
        response = bro.status()
        self.assertIn('running', response)

    def test_reload(self):
        bro = Bro.get_by_id(101)
        response = bro.reload()
        self.assertTrue(response['status'])

    def test_deploy_conf(self):
        bro = Bro.get_by_id(101)
        response = bro.deploy_conf()
        self.assertTrue(response['status'])
        response = bro.reload()
        self.assertTrue(response['status'])

    def test_deploy_rules(self):
        bro = Bro.get_by_id(101)
        response = bro.deploy_rules()
        self.assertTrue(response['status'])
        response = bro.reload()
        self.assertTrue(response['status'])

    def test_install(self):
        bro = Bro.get_by_id(101)
        response = bro.install()
        self.assertTrue(response['status'])

    def test_update(self):
        bro = Bro.get_by_id(101)
        response = bro.update()
        self.assertTrue(response['status'])

    def test_test_rules(self):
        bro = Bro.get_by_id(101)
        response = bro.test_rules()
        self.assertTrue(response['status'])
        with transaction.atomic():
            with self.assertRaises(IntegrityError):
                SignatureBro.objects.create(msg="Found root!",
                                            reference="",
                                            rule_full="test",
                                            enabled=True,
                                            created_date=self.date_now
                                            )


class IntelTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature', 'test-bro-script', 'test-bro-ruleset',
                'test-bro-conf', 'test-bro-bro', 'test-bro-intel']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_intel(self):
        self.assertEqual(len(Intel.get_all()), 2)
        intel = Intel.get_by_id(1)
        self.assertEqual(intel.indicator, "192.168.50.110")
        self.assertEqual(str(intel), "Intel::ADDR-192.168.50.110")
        with Intel.get_tmp_dir() as tmp_dir:
            self.assertEqual(Intel.store(tmp_dir), tmp_dir + "intel-1.dat")
        self.assertEqual(Intel.deploy(Bro.get_by_id(101)), {'status': True})
        Intel.import_from_csv(settings.BASE_DIR + '/bro/tests/data/test-intel.csv')
        self.assertEqual(len(Intel.get_all()), 4)
        self.assertEqual(str(Intel.get_by_id(3)), 'Intel::ADDR-10.110.56.45')
        Intel.get_by_id(3).delete()
        Intel.get_by_id(4).delete()
        intel = Intel.get_by_id(99)
        self.assertEqual(intel, None)
        with self.assertRaises(IntegrityError):
            Intel.objects.create(indicator="192.168.50.110", indicator_type="Intel::ADDR")


class CriticalStackTest(TestCase):
    fixtures = ['init', 'crontab', 'test-core-secrets', 'test-bro-signature', 'test-bro-script', 'test-bro-ruleset',
                'test-bro-conf', 'test-bro-bro', 'test-bro-critical-stack']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_critical_stack(self):
        critical_stack = CriticalStack.objects.get(id=1)
        self.assertEqual(str(critical_stack), "171eec432ef7643b835fcedc3cdd1017")
        self.assertTrue(critical_stack.deploy()['status'])
        self.assertTrue(critical_stack.list()['status'])
        self.assertIn('Pulling feed list from the Intel Marketplace.', str(critical_stack.list()['message']))
