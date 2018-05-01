import csv
import hashlib
import json
import logging
import os
import re
import subprocess
from collections import OrderedDict
from shutil import copyfile, move
from string import Template

import select2.fields
from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from core.models import Probe, ProbeConfiguration
from core.modelsmixins import CommonMixin
from core.ssh import execute, execute_copy
from core.utils import process_cmd
from rules.models import RuleSet, Rule

logger = logging.getLogger(__name__)


class Configuration(ProbeConfiguration):
    """
    Configuration for Bro IDS, Allows you to reuse the configuration.
    """
    probeconfiguration = models.OneToOneField(ProbeConfiguration, parent_link=True, related_name='bro_configuration',
                                              on_delete=models.CASCADE, editable=False)
    with open(settings.BASE_DIR + "/bro/default-broctl.cfg", encoding='utf_8') as f:
        BROCTL_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/bro/default-networks.cfg", encoding='utf_8') as f:
        NETWORKS_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/bro/default-node.cfg", encoding='utf_8') as f:
        NODE_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/bro/default-local.bro", encoding='utf_8') as f:
        LOCAL_DEFAULT = f.read()
    my_scripts = models.CharField(max_length=400, default="/usr/local/bro/share/bro/site/myscripts.bro",
                                  editable=False)
    my_signatures = models.CharField(max_length=400, default="/usr/local/bro/share/bro/site/mysignatures.sig",
                                     editable=False)
    policydir = models.CharField(max_length=400, default="/usr/local/bro/share/bro/", editable=False)
    bin_directory = models.CharField(max_length=800, default="/usr/local/bro/bin/", editable=False)
    broctl_cfg = models.CharField(max_length=400, default="/usr/local/bro/etc/broctl.cfg", editable=False)
    broctl_cfg_text = models.TextField(default=BROCTL_DEFAULT)
    node_cfg = models.CharField(max_length=400, default="/usr/local/bro/etc/node.cfg", editable=False)
    node_cfg_text = models.TextField(default=NODE_DEFAULT)
    networks_cfg = models.CharField(max_length=400, default="/usr/local/bro/etc/networks.cfg", editable=False)
    networks_cfg_text = models.TextField(default=NETWORKS_DEFAULT)
    local_bro = models.CharField(max_length=400, default="/usr/local/bro/share/bro/site/local.bro", editable=False)
    local_bro_text = models.TextField(default=LOCAL_DEFAULT)

    def __str__(self):
        return self.name

    def test(self):
        with self.get_tmp_dir("test_conf") as tmp_dir:
            # deploy conf in local
            networks_cfg = tmp_dir + "networks.cfg"
            with open(networks_cfg, 'w') as f:
                f.write(self.networks_cfg_text.replace('\r', ''))
            if os.path.exists(settings.BRO_CONFIG + "networks.cfg"):
                copyfile(settings.BRO_CONFIG + "networks.cfg", settings.BRO_CONFIG + "networks.cfg.old")
            copyfile(networks_cfg, settings.BRO_CONFIG + "networks.cfg")
            cmd = [settings.BROCTL_BINARY,
                   'check'
                   ]
            response = process_cmd(cmd, tmp_dir, "failed")
            # remove deployed conf in local by default
            move(settings.BRO_CONFIG + "networks.cfg.old", settings.BRO_CONFIG + "networks.cfg")
            return response


class SignatureBro(Rule):
    """
    Stores a signature Bro compatible. (pattern matching), see https://www.bro.org/sphinx/frameworks/signatures.html
    """
    msg = models.CharField(max_length=1000, unique=True)
    pcap_success = models.FileField(name='pcap_success', upload_to='pcap_success', blank=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sid = self.id

    def __str__(self):
        return str(self.sid) + " : " + str(self.msg)

    @classmethod
    def get_by_msg(cls, msg):
        try:
            obj = cls.objects.get(msg=msg)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the signatures"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_attributs(cls, line, rulesets=None):  # pragma: no cover TODO
        getmsg = re.compile("event *\"(.*?)\"")
        try:
            match = getmsg.search(line)
            if match:
                if SignatureBro.get_by_msg(match.groups()[0]):
                    signature = cls.get_by_msg(match.groups()[0])
                    signature.updated_date = timezone.now()
                else:
                    signature = SignatureBro()
                    signature.created_date = timezone.now()
                signature.rule_full = line
                signature.save()
                if rulesets:
                    for ruleset in rulesets:
                        ruleset.signatures.add(signature)
                        ruleset.save()
                return "rule saved : " + str(signature.sid)
        except Exception:
            return "rule not saved"

    def test(self):
        with self.get_tmp_dir("test_sig") as tmp_dir:
            rule_file = tmp_dir + str(self.sid) + ".sig"
            with open(rule_file, 'w') as f:
                f.write(self.rule_full.replace('\r', ''))
            cmd = [settings.BRO_BINARY,
                   '-s', rule_file,
                   '-r', settings.BASE_DIR + "/bro/tests/data/test-signature.pcap"
                   ]
            return process_cmd(cmd, tmp_dir, "error")

    def test_pcap(self):
        with self.get_tmp_dir("test_pcap") as tmp_dir:
            rule_file = tmp_dir + "signature.txt"
            with open(rule_file, 'w', encoding='utf_8') as f:
                f.write(self.rule_full.replace('\r', ''))
            cmd = [settings.BRO_BINARY,
                   '-r', settings.BASE_DIR + "/" + self.pcap_success.name,
                   '-s', rule_file
                   ]
            process = subprocess.Popen(cmd, cwd=tmp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            outdata, errdata = process.communicate()
            logger.debug("outdata : " + str(outdata), "errdata : " + str(errdata))
            test = False
            if os.path.isfile(tmp_dir + "signatures.log"):
                with open(tmp_dir + "signatures.log", "r", encoding='utf_8') as f:
                    if self.msg in f.read():
                        test = True
            # if success ok
        if process.returncode == 0 and test:
            return {'status': True}
            # if not -> return error
        errdata += b"Alert not generated"
        return {'status': False, 'errors': errdata}

    def test_all(self):
        test = True
        errors = list()
        response = self.test()
        if not response['status']:
            test = False
            errors.append(str(self) + " : " + str(response['errors']))
        if self.pcap_success:
            response_pcap = self.test_pcap()
            if not response_pcap['status']:
                test = False
                errors.append(str(self) + " : " + str(response_pcap['errors']))
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}


class ScriptBro(Rule):
    """
    Stores a script Bro compatible. see : https://www.bro.org/sphinx/scripting/index.html#understanding-bro-scripts
    """
    name = models.CharField(max_length=100, unique=True, verbose_name="msg in notice")
    pcap_success = models.FileField(name='pcap_success', upload_to='pcap_success', blank=True)

    def __str__(self):
        return self.name

    @classmethod
    def get_by_name(cls, name):
        try:
            obj = cls.objects.get(name=name)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the scripts"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_attributs(cls, file, rulesets=None):  # TODO Not yet implemented # pragma: no cover
        pass

    def test(self):
        with self.get_tmp_dir("test_script") as tmp_dir:
            rule_file = tmp_dir + str(self.pk) + ".bro"
            with open(rule_file, 'w') as f:
                f.write(self.rule_full.replace('\r', ''))
            cmd = [settings.BRO_BINARY,
                   '-a',
                   rule_file,
                   '-p', 'standalone', '-p', 'local', '-p', 'bro local.bro broctl broctl/standalone broctl/auto'
                   ]
            return process_cmd(cmd, tmp_dir, "error")

    def test_pcap(self):
        with self.get_tmp_dir("test_pcap") as tmp_dir:
            rule_file = tmp_dir + "script.txt"
            with open(rule_file, 'w', encoding='utf_8') as f:
                f.write(self.rule_full.replace('\r', ''))
            cmd = [settings.BRO_BINARY,
                   '-r', settings.BASE_DIR + "/" + self.pcap_success.name,
                   rule_file,
                   '-p', 'standalone', '-p', 'local', '-p', 'bro local.bro broctl broctl/standalone broctl/auto'
                   ]
            process = subprocess.Popen(cmd, cwd=tmp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            outdata, errdata = process.communicate()
            logger.debug("outdata : " + str(outdata), "errdata : " + str(errdata))
            test = False
            if os.path.isfile(tmp_dir + "notice.log"):
                with open(tmp_dir + "notice.log", "r", encoding='utf_8') as f:
                    if self.name in f.read():
                        test = True
            # if success ok
        if process.returncode == 0 and test:
            return {'status': True}
            # if not -> return error
        errdata += b"Alert not generated"
        return {'status': False, 'errors': errdata}

    def test_all(self):
        test = True
        errors = list()
        response = self.test()
        if not response['status']:
            test = False
            errors.append(str(self) + " : " + str(response['errors']))
        if self.pcap_success:
            response_pcap = self.test_pcap()
            if not response_pcap['status']:
                test = False
                errors.append(str(self) + " : " + str(response_pcap['errors']))
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}


class RuleSetBro(RuleSet):
    """Set of signatures and scripts Bro compatible"""
    signatures = select2.fields.ManyToManyField(SignatureBro,
                                                blank=True,
                                                ajax=True,
                                                search_field=lambda q: Q(sid__icontains=q),
                                                sort_field='sid',
                                                js_options={'quiet_millis': 200}
                                                )
    scripts = select2.fields.ManyToManyField(ScriptBro,
                                             blank=True,
                                             ajax=True,
                                             search_field=lambda q: Q(sid__icontains=q) | Q(name__icontains=q),
                                             sort_field='sid',
                                             js_options={'quiet_millis': 200}
                                             )

    def __str__(self):
        return self.name

    def test_rules(self):
        test = True
        errors = list()
        for signature in self.signatures.all():
            response = signature.test()
            if not response['status']:
                test = False
                errors.append(str(signature) + " : " + str(response['errors']))
        for script in self.scripts.all():
            response = script.test()
            if not response['status']:
                test = False
                errors.append(str(script) + " : " + str(response['errors']))
        if not test:
            return {'status': False, 'errors': str(errors)}
        return {'status': True}


class Bro(Probe):
    """
    Stores an instance of Bro IDS software. Configuration settings.
    """
    rulesets = models.ManyToManyField(RuleSetBro, blank=True)
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + " : " + self.description

    def install(self, version=settings.BRO_VERSION):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            install_script = """
            if ! type /usr/local/bro/bin/bro ; then
                apt update
                apt install -y cmake make gcc g++ flex bison libpcap-dev libssl1.0-dev python-dev swig zlib1g-dev \
                libmagic-dev libgeoip-dev sendmail libcap2-bin wget curl ca-certificates
                wget https://www.bro.org/downloads/bro-${version}.tar.gz
                tar xf bro-${version}.tar.gz
                ( cd bro-${version} && ./configure )
                ( cd bro-${version} && make -j$(nproc) )
                ( cd bro-${version} && make install )
                rm bro-${version}.tar.gz && rm -rf bro-${version}
                export PATH=/usr/local/bro/bin:$PATH && export LD_LIBRARY_PATH=/usr/local/bro/lib/
                echo "export PATH=/usr/local/bro/bin:$PATH" >> .bashrc
                echo "export LD_LIBRARY_PATH=/usr/local/bro/lib/" >> .bashrc
                /usr/local/bro/bin/broctl deploy
                exit 0
            else
                echo "Already installed"
                exit 0
            fi
            """
            t = Template(install_script)
            command = "sh -c '" + t.safe_substitute(version=version) + "'"
        else:  # pragma: no cover
            raise NotImplementedError
        tasks = {"install": command}
        try:
            response = execute(self.server, tasks, become=True)
            self.installed = True
            self.save()
        except Exception as e:  # pragma: no cover
            logger.exception('install failed')
            return {'status': False, 'errors': str(e)}
        logger.debug("output : " + str(response))
        return {'status': True}

    def update(self, version=settings.BRO_VERSION):
        return self.install(version=version)

    def start(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = self.configuration.bin_directory + "broctl start"
        else:  # pragma: no cover
            raise NotImplementedError
        tasks = {"start": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:  # pragma: no cover
            logger.exception("Error during start")
            return {'status': False, 'errors': "Error during start"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def stop(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = self.configuration.bin_directory + "broctl stop"
        else:  # pragma: no cover
            raise NotImplementedError
        tasks = {"stop": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:  # pragma: no cover
            logger.exception("Error during stop")
            return {'status': False, 'errors': "Error during stop"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def status(self):
        if self.installed:
            if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
                command = self.configuration.bin_directory + "broctl status | sed -n 2p"
            else:  # pragma: no cover
                raise NotImplementedError
            tasks = {"status": command}
            try:
                response = execute(self.server, tasks, become=True)
            except Exception:  # pragma: no cover
                logger.exception('Failed to get status')
                return 'Failed to get status'
            logger.debug("output : " + str(response))
            if response['status'] == "OK":
                return ""
            else:
                return response['status']
        else:
            return 'Not installed'

    def uptime(self):
        return self.status()

    def reload(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = self.configuration.bin_directory + "broctl deploy"
        else:  # pragma: no cover
            raise NotImplementedError
        tasks = {"1_deploy": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:  # pragma: no cover
            print("output : " + str(e))
            logger.exception("Error during reload")
            return {'status': False, 'errors': "Error during reload"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def restart(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command1 = self.configuration.bin_directory + "broctl stop"
            command2 = self.configuration.bin_directory + "broctl deploy"
        else:  # pragma: no cover
            raise NotImplementedError
        tasks_unordered = {"1_stop": command1,
                           "3_deploy": command2}
        tasks = OrderedDict(sorted(tasks_unordered.items(), key=lambda t: t[0]))
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:  # pragma: no cover
            logger.exception("Error during restart")
            return {'status': False, 'errors': "Error during restart"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def test_rules(self):
        test = True
        errors = list()
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                response = signature.test()
                if not response['status']:
                    test = False
                    errors.append(str(response['errors']))
            for script in ruleset.scripts.all():
                response = script.test()
                if not response['status']:
                    test = False
                    errors.append(str(script) + " : " + str(response['errors']))
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}

    def deploy_rules(self):
        deploy = True
        response = dict()
        errors = list()
        value_signatures = ""
        value_scripts = ""
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                if signature.enabled:
                    value_signatures += signature.rule_full + '\n'
            for script in ruleset.scripts.all():
                if script.enabled:
                    value_scripts += script.rule_full + '\n'
        with self.get_tmp_dir(self.pk) as tmp_dir:
            with open(tmp_dir + "signatures.txt", 'w', encoding='utf_8') as f:
                f.write(value_signatures.replace('\r', ''))
            try:
                response = execute_copy(self.server, src=tmp_dir + 'signatures.txt',
                                        dest=self.configuration.my_signatures,
                                        become=True)
            except Exception as e:  # pragma: no cover
                logger.exception('excecute_copy failed')
                deploy = False
                errors.append(str(e))
            with open(tmp_dir + "scripts.txt", 'w', encoding='utf_8') as f:
                f.write(value_scripts.replace('\r', ''))
            try:
                response = execute_copy(self.server, src=tmp_dir + 'scripts.txt',
                                        dest=self.configuration.my_scripts,
                                        become=True)
            except Exception as e:  # pragma: no cover
                logger.exception('excecute_copy failed')
                deploy = False
                errors.append(str(e))
            logger.debug("output : " + str(response))
        result = self.reload()
        if deploy and result['status']:
            self.rules_updated_date = timezone.now()
            self.save()
            return {"status": deploy}
        else:  # pragma: no cover
            return {'status': deploy, 'errors': errors}

    def deploy_conf(self):
        with self.get_tmp_dir(self.pk) as tmp_dir:
            with open(tmp_dir + "broctl_cfg.conf", 'w', encoding='utf_8') as f:
                f.write(self.configuration.broctl_cfg_text.replace('\r', ''))
            with open(tmp_dir + "node_cfg.conf", 'w', encoding='utf_8') as f:
                f.write(self.configuration.node_cfg_text.replace('\r', ''))
            with open(tmp_dir + "networks_cfg.conf", 'w', encoding='utf_8') as f:
                f.write(self.configuration.networks_cfg_text.replace('\r', ''))
            with open(tmp_dir + "local_bro.conf", 'w', encoding='utf_8') as f:
                f.write(self.configuration.local_bro_text.replace('\r', ''))
            deploy = True
            errors = list()
            response = dict()
            try:
                response = execute_copy(self.server, src=os.path.abspath(tmp_dir + 'broctl_cfg.conf'),
                                        dest=self.configuration.broctl_cfg, become=True)
                response = execute_copy(self.server, src=os.path.abspath(tmp_dir + 'node_cfg.conf'),
                                        dest=self.configuration.node_cfg, become=True)
                response = execute_copy(self.server, src=os.path.abspath(tmp_dir + 'networks_cfg.conf'),
                                        dest=self.configuration.networks_cfg, become=True)
                response = execute_copy(self.server, src=os.path.abspath(tmp_dir + 'local_bro.conf'),
                                        dest=self.configuration.local_bro, become=True)
                response = execute_copy(self.server, src=os.path.abspath(settings.BASE_DIR + '/bro/default-intel.bro'),
                                        dest=self.configuration.policydir + 'site/intel.bro', become=True)
                self.reload()
            except Exception as e:  # pragma: no cover
                logger.exception('deploy conf failed')
                deploy = False
                errors.append(str(e))
            logger.debug("output : " + str(response))
        if deploy:
            return {'status': deploy}
        else:  # pragma: no cover
            return {'status': deploy, 'errors': errors}

    def delete(self, **kwargs):
        try:
            periodic_task = PeriodicTask.objects.get(
                name=self.name + "_deploy_rules_" + str(self.scheduled_rules_deployment_crontab))
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        try:
            periodic_task = PeriodicTask.objects.get(name=self.name + "_check_task")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        return super().delete(**kwargs)


class Intel(CommonMixin, models.Model):
    """
    Store an instance of an Intel data.
    "#fields indicator       indicator_type  meta.source     meta.desc       meta.url"
    """
    class Meta:
        unique_together = ("indicator", "indicator_type")

    TYPE_CHOICES = (
        ('Intel::ADDR', 'Intel::ADDR'),
        ('Intel::SUBNET', 'Intel::SUBNET'),
        ('Intel::URL', 'Intel::URL'),
        ('Intel::SOFTWARE', 'Intel::SOFTWARE'),
        ('Intel::EMAIL', 'Intel::EMAIL'),
        ('Intel::DOMAIN', 'Intel::DOMAIN'),
        ('Intel::USER_NAME', 'Intel::USER_NAME'),
        ('Intel::CERT_HASH', 'Intel::CERT_HASH'),
        ('Intel::PUBKEY_HASH', 'Intel::PUBKEY_HASH'),
        ('Intel::FILE_HASH', 'Intel::FILE_HASH'),
        ('Intel::FILE_NAME', 'Intel::FILE_NAME'),
        ('Intel::PUBKEY_HASH', 'Intel::PUBKEY_HASH'),
    )
    indicator = models.CharField(max_length=300, null=False, blank=False)
    indicator_type = models.CharField(max_length=200, choices=TYPE_CHOICES)
    meta_source = models.CharField(max_length=300, default='-')
    meta_desc = models.CharField(max_length=300, default='-')
    meta_url = models.CharField(max_length=300, default='-')

    def __str__(self):
        return str(self.indicator_type) + "-" + str(self.indicator)

    @classmethod
    def store(cls, tmp_dir):
        tmp_file = tmp_dir + "intel-1.dat"
        with open(tmp_file, 'a', encoding='utf_8', newline='\n') as f:
            f.write("#indicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url")
            for intel in cls.get_all():
                f.write(intel.indicator + "\t" + intel.indicator_type + "\t"
                        + intel.meta_source + "\t" + intel.meta_desc + "\t" + intel.meta_url)
        return tmp_file

    @classmethod
    def deploy(cls, bro_instance):
        deploy = True
        errors = ""
        response = dict()
        try:
            with cls.get_tmp_dir() as tmp_dir:
                intel_file = cls.store(tmp_dir)
                response = execute_copy(bro_instance.server, src=intel_file,
                                        dest=bro_instance.configuration.policydir + 'site/' +
                                                                                    os.path.basename(intel_file),
                                        become=True)
        except Exception as e:  # pragma: no cover
            logger.exception('excecute_copy failed')
            deploy = False
            errors = str(e)
        if deploy:
            return {'status': deploy}
        else:  # pragma: no cover
            return {'status': deploy, 'errors': errors + ' - ' + str(response)}

    @classmethod
    def import_from_csv(cls, csv_file):
        with open(csv_file, newline='') as file:
            reader = csv.DictReader(file, fieldnames=['indicator', 'indicator_type',
                                                      'meta_source', 'meta_desc', 'meta_url'], delimiter=',')
            for row in reader:
                cls.objects.create(indicator=row['indicator'],
                                   indicator_type=row['indicator_type'],
                                   meta_source=row['meta_source'],
                                   meta_desc=row['meta_desc'],
                                   meta_url=row['meta_url'],)


class CriticalStack(models.Model):
    api_key = models.CharField(max_length=300, null=False, blank=False, unique=True)
    scheduled_pull = models.ForeignKey(CrontabSchedule, related_name='crontabschedule_pull', blank=False,
                                       null=False, on_delete=models.CASCADE)
    bros = models.ManyToManyField(Bro)

    def __str__(self):
        return str(hashlib.md5(str(self.api_key).encode(encoding='UTF-8')).hexdigest())

    def deploy(self):
        errors = list()
        for bro in self.bros.all():
            command1 = "critical-stack-intel api " + str(self.api_key)
            command2 = "critical-stack-intel config --set bro.restart=true"
            command3 = "critical-stack-intel pull"
            tasks_unordered = {"1_set_api": command1, "2_set_restart": command2, "3_pull": command3}
            tasks = OrderedDict(sorted(tasks_unordered.items(), key=lambda t: t[0]))
            try:
                response = execute(bro.server, tasks, become=True)
            except Exception as e:  # pragma: no cover
                logger.exception('deploy failed for ' + str(bro))
                errors.append('deploy failed for ' + str(bro) + ': ' + str(e))
            else:
                logger.debug("output : " + str(response))
        if errors:
            return {'status': False, 'errors': str(errors)}
        else:
            return {'status': True}

    def list(self):
        errors = list()
        success = list()
        for bro in self.bros.all():
            command1 = "critical-stack-intel api " + str(self.api_key)
            command2 = "critical-stack-intel list"
            tasks_unordered = {"1_set_api": command1, "2_list": command2}
            tasks = OrderedDict(sorted(tasks_unordered.items(), key=lambda t: t[0]))
            try:
                response = execute(bro.server, tasks, become=True)
            except Exception as e:  # pragma: no cover
                logger.exception('list failed for ' + str(bro))
                errors.append('list failed for ' + str(bro) + ': ' + str(e))
            else:
                logger.debug("output : " + str(response))
                success.append(response['2_list'])
        if errors:
            return {'status': False, 'errors': str(errors)}
        else:
            return {'status': True, 'message': str(success)}

    def delete(self, **kwargs):
        try:
            periodic_task = PeriodicTask.objects.get(
                name=str(self) + "_deploy_critical_stack")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        return super().delete(**kwargs)

    def save(self, **kwargs):
        super().save(**kwargs)
        PeriodicTask.objects.create(crontab=self.scheduled_pull,
                                    name=str(self) + "_deploy_critical_stack",
                                    task='bro.tasks.deploy_critical_stack',
                                    args=json.dumps([self.api_key, ])
                                    )
