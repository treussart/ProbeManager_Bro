import glob
import logging
import os
import subprocess
from collections import OrderedDict

import select2.fields
from django.conf import settings
from django.db import models
from django.db.models import Q

from core.models import Probe, ProbeConfiguration
from core.ssh import execute
from rules.models import RuleSet, Rule

logger = logging.getLogger(__name__)


class Configuration(ProbeConfiguration):
    """
    Configuration for Bro IDS, Allows you to reuse the configuration.
    """
    with open(settings.BASE_DIR + "/bro/default-broctl.cfg", encoding='utf_8') as f:
        BROCTL_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/bro/default-networks.cfg", encoding='utf_8') as f:
        NETWORKS_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/bro/default-node.cfg", encoding='utf_8') as f:
        NODE_DEFAULT = f.read()
    with open(settings.BASE_DIR + "/bro/default-local.bro", encoding='utf_8') as f:
        LOCAL_DEFAULT = f.read()
    policydir = models.CharField(max_length=400, default="/usr/local/bro/share/bro/policy/")
    bin_directory = models.CharField(max_length=800, default="/usr/local/bro/bin/")
    broctl_cfg = models.CharField(max_length=400, default="/usr/local/bro/etc/broctl.cfg")
    broctl_cfg_text = models.TextField(default=BROCTL_DEFAULT)
    node_cfg = models.CharField(max_length=400, default="/usr/local/bro/etc/node.cfg")
    node_cfg_text = models.TextField(default=NODE_DEFAULT)
    networks_cfg = models.CharField(max_length=400, default="/usr/local/bro/etc/networks.cfg")
    networks_cfg_text = models.TextField(default=NETWORKS_DEFAULT)
    local_bro = models.CharField(max_length=400, default="/etc/bro/site/local.bro")
    local_bro_text = models.TextField(default=LOCAL_DEFAULT)

    def __str__(self):
        return self.name

    def test(self):  # TODO Not yet implemented
        pass


class SignatureBro(Rule):
    """
    Stores a signature Bro compatible. (pattern matching), see https://www.bro.org/sphinx/frameworks/signatures.html
    """
    msg = models.CharField(max_length=1000)

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
    def find(cls, pattern):
        """Search the pattern in all the signatures"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_signature_attributs(cls, line, rulesets=None):  # TODO Not yet implemented
        pass

    def test(self):
        with self.get_tmp_dir("test_sig") as tmp_dir:
            rule_file = tmp_dir + str(self.sid) + ".sig"
            with open(rule_file, 'w') as f:
                f.write(self.rule_full)
            cmd = [settings.BRO_BINARY,
                   '-a', '-S',
                   '-s', rule_file
                   ]
            process = subprocess.Popen(cmd, cwd=tmp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outdata, errdata) = process.communicate()
            logger.debug(outdata)
            # if success ok
            if "Error in signature" in outdata:
                return {'status': False, 'errors': errdata}
            else:
                return {'status': True}


class ScriptBro(Rule):
    """
    Stores a script Bro compatible. see : https://www.bro.org/sphinx/scripting/index.html#understanding-bro-scripts
    """
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def find(cls, pattern):
        """Search the pattern in all the scripts"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_script_attributs(cls, file, rulesets=None):  # TODO Not yet implemented
        pass

    def test(self):
        with self.get_tmp_dir("test_script") as tmp_dir:
            rule_file = tmp_dir + str(self.id) + ".bro"
            with open(rule_file, 'w') as f:
                f.write(self.rule_full)
            cmd = [settings.BRO_BINARY,
                   '-a', '-S',
                   '-s', rule_file
                   ]
            process = subprocess.Popen(cmd, cwd=tmp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outdata, errdata) = process.communicate()
            logger.debug(outdata)
            # if success ok
            if "Error in script" in outdata:
                return {'status': False, 'errors': errdata}
            else:
                return {'status': True}


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

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


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

    def install(self, version="2.5.3"):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command1 = "apt update"
            command2 = "apt install cmake make gcc g++ flex bison libpcap-dev libssl1.0-dev python-dev swig " \
                       "zlib1g-dev libmagic-dev libgeoip-dev sendmail libcap2-bin " \
                       "wget curl ca-certificates "
            command3 = "wget https://www.bro.org/downloads/bro-" + version + ".tar.gz"
            command4 = "tar xf bro-" + version + ".tar.gz"
            command5 = "( cd bro-" + version + " && ./configure )"
            command6 = "( cd bro-" + version + " && make -j$(nproc) )"
            command7 = "( cd bro-" + version + " && make install )"
            command8 = "rm bro-" + version + ".tar.gz && rm -rf bro-" + version
            command9 = "export PATH=/usr/local/bro/bin:$PATH && export LD_LIBRARY_PATH=/usr/local/bro/lib/"
        else:
            raise Exception("Not yet implemented")
        tasks_unordered = {"1_update_repo": command1,
                           "2_install_dep": command2,
                           "3_download": command3,
                           "4_tar": command4,
                           "5_configure": command5,
                           "6_make": command6,
                           "7_make_install": command7,
                           "8_rm": command8,
                           "9_export": command9}
        tasks = OrderedDict(sorted(tasks_unordered.items(), key=lambda t: t[0]))
        try:
            response = execute(self.server, tasks, become=True)
            self.installed = True
            self.save()
        except Exception as e:
            logger.exception('install failed')
            return {'status': False, 'errors': str(e)}
        logger.debug("output : " + str(response))
        return {'status': True}

    def update(self):
        return self.install()

    def start(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = settings.BROCTL_BINARY + " start"
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
            command = settings.BROCTL_BINARY + " stop"
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
                command = settings.BROCTL_BINARY + " status"
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

    def reload(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = settings.BROCTL_BINARY + " deploy"
        else:  # pragma: no cover
            raise Exception("Not yet implemented")
        tasks = {"reload": command}
        try:
            response = execute(self.server, tasks, become=True)
        except Exception:
            logger.exception("Error during reload")
            return {'status': False, 'errors': "Error during reload"}
        logger.debug("output : " + str(response))
        return {'status': True}

    def restart(self):
        if self.server.os.name == 'debian' or self.server.os.name == 'ubuntu':
            command = settings.BROCTL_BINARY + " deploy"
        else:  # pragma: no cover
            raise Exception("Not yet implemented")
        tasks = {"restart": command}
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
        if test:
            return {'status': True}
        else:
            return {'status': False, 'errors': errors}

    def deploy_rules(self):  # TODO
        # Signatures
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        value = ""
        for ruleset in self.rulesets.all():
            for signature in ruleset.signatures.all():
                if signature.enabled:
                    value += signature.rule_full + os.linesep
        f = open(tmpdir + "temp.rules", 'w')
        f.write(value)
        f.close()

        # Scripts
        scripts_to_deploy = []
        for ruleset in self.rulesets.all():
            for script in ruleset.scripts.all():
                if script.enabled:
                    f = open(tmpdir + script.name, 'w')
                    f.write(script.rule_full)
                    f.close()
                    scripts_to_deploy.append(
                        dict(name="deploy_rules", action=dict(module='copy', src=tmpdir + script.name,
                                                              dest=self.configuration.conf_script_directory.rstrip(
                                                                  '/') + '/' + script.name,
                                                              owner='root', group='root', mode='0600')))

        tasks = [
            dict(name="copy", action=dict(module='copy', src=tmpdir + 'temp.rules',
                                          dest=self.configuration.conf_rules_directory.rstrip('/') + '/deployed.rules',
                                          owner='root', group='root', mode='0600')
                 ),
        ]
        tasks += scripts_to_deploy
        response = execute(self.server, tasks)
        for file in glob.glob(tmpdir + '*.lua'):
            os.remove(tmpdir + file)
        if os.path.isfile(tmpdir + 'temp.rules'):
            os.remove(tmpdir + "temp.rules")
        return response

    def deploy_conf(self):  # TODO
        tmpdir = settings.BASE_DIR + "/tmp/" + self.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        value = self.configuration.conf_advanced_text
        f = open(tmpdir + "temp.conf", 'w')
        f.write(value)
        f.close()
        tasks = [
            dict(name="deploy_conf", action=dict(module='copy', src=os.path.abspath(tmpdir + 'temp.conf'),
                                                 dest=self.configuration.conf_file, owner='root', group='root',
                                                 mode='0600')),
        ]
        response = execute(self.server, tasks)
        if os.path.isfile(tmpdir + 'temp.conf'):
            os.remove(tmpdir + "temp.conf")
        return response


class PcapTestSuricata(models.Model):
    """
    Stores a Pcap file for testing signature or script.
    """
    signature = select2.fields.ForeignKey(SignatureBro,
                                          limit_choices_to=models.Q(enabled=True),
                                          ajax=True,
                                          search_field='id',
                                          overlay="Choose a signature...",
                                          js_options={
                                              'quiet_millis': 200,
                                          },
                                          on_delete=models.CASCADE
                                          )
    probe = models.ForeignKey(Bro)
    pcap_success = models.FileField(name='pcap_success', upload_to='tmp/pcap/', blank=True)

    # pcap_fail = models.FileField(name='pcap_fail', upload_to=tmpdir, blank=True)

    def __str__(self):
        return str(self.signature) + "  " + str(self.probe)

    def test(self):
        tmpdir = settings.BASE_DIR + "/tmp/pcap/" + str(self.signature.sid) + "/" + self.probe.name + "/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        rule_file = tmpdir + str(self.signature.sid) + ".sig"
        with open(rule_file, 'w') as f:
            f.write(self.signature.rule_full)
        cmd = [settings.BRO_BINARY + "bro",
               '-r', settings.BASE_DIR + "/" + self.pcap_success.name,
               '-s', rule_file
               ]
        process = subprocess.Popen(cmd, cwd=tmpdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = process.communicate()
        logger.debug(outdata)
        f.close()
        success = False
        # if success ok
        if os.path.isfile(tmpdir + "signatures.log"):
            with open(tmpdir + "signatures.log", 'r') as f:
                if self.signature.msg in f.read():
                    success = True
        # Remove files
        os.remove(rule_file)
        for file in glob.glob(tmpdir + "*.log"):
            os.remove(file)
        if success:
            return {'status': True}
        else:
            return {'status': False, 'errors': errdata}
