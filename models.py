from django.db import models
from home.ssh import execute
from home.models import Probe, ProbeConfiguration
from rules.models import RuleSet, Rule
import logging
import os
import glob
import subprocess
import select2.fields
from django.db.models import Q
from django.conf import settings


logger = logging.getLogger(__name__)


class ConfBro(ProbeConfiguration):
    """
    Configuration for Bro IDS, Allows you to reuse the configuration.
    """
    conf_rules_directory = models.CharField(max_length=400)
    conf_file = models.CharField(max_length=800)
    bin_directory = models.CharField(max_length=800)

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

    def test(self):  # TODO Not yet implemented
        pass


class SignatureBro(Rule):
    """
    Stores a signature Bro compatible. (pattern matching), see https://www.bro.org/sphinx/frameworks/signatures.html
    """
    msg = models.CharField(max_length=1000)

    def __init__(self, *args, **kwargs):
        super(Rule, self).__init__(*args, **kwargs)
        self.sid = self.id

    def __str__(self):
        return str(self.sid) + " : " + str(self.msg)

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
        """Search the pattern in all the signatures"""
        return cls.objects.filter(rule_full__contains=pattern)

    @classmethod
    def extract_signature_attributs(cls, line, rulesets=None):  # TODO Not yet implemented
        pass

    def test(self):  # TODO Not yet implemented
        tmpdir = settings.BASE_DIR + "/tmp/test_sig/"
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        rule_file = tmpdir + str(self.sid) + ".sig"
        with open(rule_file, 'w') as f:
            f.write(self.rule_full)
        cmd = [settings.BRO_BINARY + "bro",
               '-r', settings.BASE_DIR + '/bro/tests/data/test.pcap',
               '-s', rule_file
               ]
        process = subprocess.Popen(cmd, cwd=tmpdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = process.communicate()
        logger.debug(outdata)
        f.close()
        # Remove files
        os.remove(rule_file)
        for file in glob.glob(tmpdir + "*.log"):
            os.remove(file)
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

    def test(self):  # TODO Not yet implemented
        pass


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
    configuration = models.ForeignKey(ConfBro)

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + " : " + self.description

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

    def install(self):
        path = "/opt"
        list_package = ["wget", "curl", "ca-certificates", "build-essential", "tcpdump", "cmake", "make", "gcc", "g++", "flex", "bison", "libpcap-dev", "python-dev", "swig", "zlib1g-dev", "tshark", "libssl1.0-dev", "libgeoip-dev", "git"]
        list_install = list()
        for package in list_package:
            list_install.append(dict(name="apt_install", action=dict(module='apt', name=package, state='present', update_cache='yes')))
        tasks = [
            dict(name="apt_install", action=dict(module='shell', args='apt install python3-apt')),
        ]
        tasks = tasks + list_install
        list_action = [
            dict(name="wget", action=dict(module='shell', chdir=path, args='wget https://www.bro.org/downloads/bro-2.5.2.tar.gz')),
            dict(name="tar_extract", action=dict(module='shell', chdir=path, args='tar xvf bro-2.5.2.tar.gz')),
            dict(name="configure", action=dict(module='shell', chdir=path + "/bro-2.5.2/", args='./configure')),
            dict(name="make", action=dict(module='shell', chdir=path + "/bro-2.5.2/", args='make')),
            dict(name="make_install", action=dict(module='shell', chdir=path + "/bro-2.5.2/", args='make install')),
            dict(name="export_PATH", action=dict(module='shell', chdir=path, args='export PATH=/usr/local/bro/bin:$PATH')),
            dict(name="export LD_LIBRARY", action=dict(module='shell', chdir=path, args='export LD_LIBRARY_PATH=/usr/local/bro/lib/')),
            dict(name="git_af_packet-plugin", action=dict(module='shell', chdir=path, args='git clone https://github.com/J-Gras/bro-af_packet-plugin.git')),
            dict(name="af_packet-plugin_configure", action=dict(module='shell', chdir=path + "/bro-af_packet-plugin/", args='./configure')),
            dict(name="af_packet-plugin_make", action=dict(module='shell', chdir=path + "/bro-af_packet-plugin/", args='make')),
            dict(name="af_packet-plugin_make_install", action=dict(module='shell', chdir=path + "/bro-af_packet-plugin/", args='make install')),
        ]
        tasks = tasks + list_action
        return execute(self, tasks)

    def start(self):
        tasks = [
            dict(name="start", action=dict(module='shell', args=self.configuration.bin_directory + 'broctl start')),
        ]
        return execute(self.server, tasks)

    def stop(self):
        tasks = [
            dict(name="stop", action=dict(module='shell', args=self.configuration.bin_directory + 'broctl stop')),
        ]
        return execute(self, tasks)

    def restart(self):
        tasks = [
            dict(name="restart", action=dict(module='shell', args=self.configuration.bin_directory + 'broctl deploy')),
        ]
        return execute(self.server, tasks)

    def status(self):
        tasks = [
            dict(name="status", action=dict(module='shell', args=self.configuration.bin_directory + 'broctl status')),
        ]
        return execute(self.server, tasks)

    def reload(self):
        tasks = [
            dict(name="reload", action=dict(module='shell', args=self.configuration.bin_directory + 'broctl deploy')),
        ]
        return execute(self.server, tasks)

    def update(self):  # Not implemented
        return None

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
                    scripts_to_deploy.append(dict(name="deploy_rules", action=dict(module='copy', src=tmpdir + script.name,
                                                  dest=self.configuration.conf_script_directory.rstrip('/') + '/' + script.name,
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
            dict(name="deploy_conf", action=dict(module='copy', src=os.path.abspath(tmpdir + 'temp.conf'), dest=self.configuration.conf_file, owner='root', group='root', mode='0600')),
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
