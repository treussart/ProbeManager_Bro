import logging
import os
import re
import subprocess
from collections import OrderedDict
from string import Template

import select2.fields
from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from core.models import Probe, ProbeConfiguration
from core.ssh import execute, execute_copy
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
    policydir = models.CharField(max_length=400, default="/usr/local/bro/share/bro/policy/", editable=False)
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

    def test(self):  # TODO Not yet implemented
        return {'status': True}


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
    def get_by_sid(cls, sid):
        try:
            obj = cls.objects.get(sid=sid)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj

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
    def extract_signature_attributs(cls, line, rulesets=None):
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
            process = subprocess.Popen(cmd, cwd=tmp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outdata, errdata) = process.communicate()
            logger.debug(outdata)
            # if success ok
            if b"Error in signature" in outdata:
                return {'status': False, 'errors': errdata}
            else:
                return {'status': True}

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
            (outdata, errdata) = process.communicate()
            logger.debug(outdata)
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
    def find(cls, pattern):
        """Search the pattern in all the scripts"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_script_attributs(cls, file, rulesets=None):  # TODO Not yet implemented
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
            process = subprocess.Popen(cmd, cwd=tmp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outdata, errdata) = process.communicate()
            logger.debug(outdata)
            # if success ok
            if b"error in " in outdata:
                return {'status': False, 'errors': errdata}
            else:
                return {'status': True}

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
            (outdata, errdata) = process.communicate()
            logger.debug(outdata)
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
            command = "sh -c '" + t.substitute(version=version) + "'"
        else:
            raise Exception("Not yet implemented")
        tasks = {"install": command}
        try:
            response = execute(self.server, tasks, become=True)
            self.installed = True
            self.save()
        except Exception as e:
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
            raise Exception("Not yet implemented")
        tasks = {"start": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:
            logger.exception("Error during start")
            return {'status': False, 'errors': "Error during start"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def stop(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = self.configuration.bin_directory + "broctl stop"
        else:  # pragma: no cover
            raise Exception("Not yet implemented")
        tasks = {"stop": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:
            logger.exception("Error during stop")
            return {'status': False, 'errors': "Error during stop"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def status(self):
        if self.installed:
            if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
                command = self.configuration.bin_directory + "broctl status | sed -n 2p"
            else:  # pragma: no cover
                raise Exception("Not yet implemented")
            tasks = {"status": command}
            try:
                response = execute(self.server, tasks, become=True)
            except Exception:
                logger.exception('Failed to get status')
                return 'Failed to get status'
            logger.debug("output : " + str(response))
            return response['status']
        else:
            return " "

    def uptime(self):
        return self.status()

    def reload(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = self.configuration.bin_directory + "broctl deploy"
        else:  # pragma: no cover
            raise Exception("Not yet implemented")
        tasks = {"1_deploy": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception as e:
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
            raise Exception("Not yet implemented")
        tasks_unordered = {"1_stop": command1,
                           "3_deploy": command2}
        tasks = OrderedDict(sorted(tasks_unordered.items(), key=lambda t: t[0]))
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:
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
            except Exception as e:
                logger.exception('excecute_copy failed')
                deploy = False
                errors.append(str(e))
            with open(tmp_dir + "scripts.txt", 'w', encoding='utf_8') as f:
                f.write(value_scripts.replace('\r', ''))
            try:
                response = execute_copy(self.server, src=tmp_dir + 'scripts.txt',
                                        dest=self.configuration.my_scripts,
                                        become=True)
            except Exception as e:
                logger.exception('excecute_copy failed')
                deploy = False
                errors.append(str(e))
            logger.debug("output : " + str(response))
        result = self.reload()
        if deploy and result['status']:
            self.rules_updated_date = timezone.now()
            self.save()
            return {"status": deploy}
        else:
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
                self.reload()
            except Exception as e:
                logger.exception('deploy conf failed')
                deploy = False
                errors.append(str(e))
            logger.debug("output : " + str(response))
        if deploy:
            return {'status': deploy}
        else:
            return {'status': deploy, 'errors': errors}
