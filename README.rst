*********************
Bro for Probe Manager
*********************


|Licence| |Version|

.. image:: https://api.codacy.com/project/badge/Grade/f5e3cb111fc949d08287c36ce4fa5798?branch=develop
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/treussart/ProbeManager_Bro?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Bro&amp;utm_campaign=Badge_Grade

.. image:: https://api.codacy.com/project/badge/Grade/f5e3cb111fc949d08287c36ce4fa5798?branch=develop
   :alt: Codacy Coverage
   :target: https://www.codacy.com/app/treussart/ProbeManager_Bro?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_Bro&amp;utm_campaign=Badge_Coverage

.. |Licence| image:: https://img.shields.io/github/license/treussart/ProbeManager_Bro.svg
.. |Version| image:: https://img.shields.io/github/tag/treussart/ProbeManager_Bro.svg


Presentation
============

Module for `Bro IDS <https://www.bro.org/>`_


Compatible version
------------------

* Bro version 2.5.3 RELEASE


Features
--------

* Install and update Bro NIDS on a remote server.
* Configure the settings and test the configuration.
* Add, Delete, Update scripts and signatures.
* Test signatures and scripts compliance.
* Test signatures and scripts via Pcap.
* Add data to the `Intelligence Framework <https://www.bro.org/sphinx-git/scripts/base/frameworks/intel/main.bro.html>`_ (IP, URL, Domain ...) possibility to import them in csv format.
* Group rules into groups and assign them to probes.
* Pull feeds from `Critical Stack <https://intel.criticalstack.com/>`_.


Installation
============

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_

Usage
=====

Administration Page of the module :
-----------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-index.png
  :align: center
  :width: 80%

Page to add a Bro IDS instance :
--------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-bro-add.png
  :align: center
  :width: 70%

* Name: Give a unique name for this instance, example: server-tap1_bro.
* Secure deployment: Specify if you want rules to be verified at each deployment.
* Scheduled rules deployment enabled: Enable scheduled deployment of rules.
* Scheduled check enabled: Enable instance monitoring. (Check if the probe is active)
* Server: Specify the server for the probe.
* Probe already installed: Specify if the probe is already installed.
* Rulesets: Choose the sets of rules that will be deployed on this probe.
* Configuration: Give the configuration of the probe.

Page to add a configuration :
-----------------------------

Allows you to modify the `Bro configuration <https://www.bro.org/sphinx/quickstart/index.html#a-minimal-starting-configuration>`_.

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-conf-add.png
  :align: center
  :width: 80%

* broctl.cfg: Change the MailTo email address to a desired recipient and the LogRotationInterval to a desired log archival frequency.
* node.cfg: Set the right interface to monitor.
* networks.cfg: Comment out the default settings and add the networks that Bro will consider local to the monitored environment.
* local.bro: The main entry point for the default analysis configuration of a standalone Bro instance managed by BroControl.

Page to add a Bro Intel :
-------------------------

Allows you to add a `Bro Intel <https://www.bro.org/sphinx-git/frameworks/intel.html>`_.

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-intel-add.png
  :align: center
  :width: 60%

* indicator: The value
* indicator_type: `List of types available <https://www.bro.org/sphinx-git/scripts/base/frameworks/intel/main.bro.html#type-Intel::Type>`_.
* meta.source: An arbitrary string value representing the data source. This value is used as a unique key to identify a metadata record in the scope of a single intelligence item.
* meta.desc: A freeform description for the data.
* meta.url: A URL for more information about the data.

Intels are deployed at each deployment of the rules by a Bro instance.


Page to add a Critical Stack client on a Bro instance :
-------------------------------------------------------

`Critical Stack client <https://criticalstack.zendesk.com/hc/en-us/articles/203408139-Full-Documentation-all-the-things->`_.

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-criticalstack-add.png
  :align: center
  :width: 70%

* API Key: API Key of your Sensor.
* Schedulled pull: Give a crontab to plan a pull of intel from feeds.
* Bros: Select Bro instances to apply.

Page of an instance :
---------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/instance-index.png
  :align: center
  :width: 80%

* 'Uptime' Indicate the time elapsed since the last time the application was started.
* 'Refresh Instance Status' is a button to know the status of the application (running or not).
* 'Update instance', you need to edit the configuration file to change the version number you want.
* 'Deploy configuration', copy configuration files to the remote server, and reload the Bro instance.
* 'Deploy rules', copy rules (signatures and scripts) files to the remote server, and reload the Bro instance.

Miscellaneous
-------------

The problem with Bro scripts is that they are not necessarily independent of each other, which is why it's complicated to test them.
TODO : To solve this problem, it will be necessary to test all the scripts of an instance at the same time.
