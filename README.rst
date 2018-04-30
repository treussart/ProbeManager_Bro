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
 * Tests signatures and scripts compliance.
 * Tests signatures and scripts if generates notice via Pcap.
 * Adding data in the Intelligence Framework (IP, URL, Domain ...) possibility to import them in csv format.
 * Grouping rules into groups and assign this to probes.
 * Pull feeds from `Critical Stack <https://intel.criticalstack.com/>`_.


Installation
============

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_

Usage
=====

.. |Admin page| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-index.png
.. |Admin page for add a bro instance| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-bro-add.png
.. |Admin page for add a conf| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-conf-add.png
.. |Admin page for add a intel| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-intel-add.png
.. |Admin page for add a criticalstack| image:: https://raw.githubusercontent.com/treussart/ProbeManager_Bro/develop/data/admin-criticalstack-add.png


Administration Page of the module :
-----------------------------------

|Admin page|

Page to add a Bro IDS instance :
--------------------------------

|Admin page for add a bro instance|

 * Give a unique name for this instance, example: server-tap1_bro.
 * Specify if you want rules to be verified at each deployment.
 * Enable scheduled deployment of rules.
 * Enable instance monitoring. (Check if the probe is active)
 * Specify the server for the probe.
 * Specify if the probe is already installed.
 * Choose the sets of rules that will be deployed on this probe.
 * Give the configuration of the probe.

Page to add a configuration :
-----------------------------

Allows you to modify the `Bro configuration <https://www.bro.org/sphinx/quickstart/index.html#a-minimal-starting-configuration>`_.

|Admin page for add a conf|

 * broctl.cfg, change the MailTo email address to a desired recipient and the LogRotationInterval to a desired log archival frequency.
 * node.cfg, set the right interface to monitor.
 * networks.cfg, comment out the default settings and add the networks that Bro will consider local to the monitored environment.
 * local.bro, The main entry point for the default analysis configuration of a standalone Bro instance managed by BroControl.

Page to add a Bro Intel :
-------------------------

Allows you to add a `Bro Intel <https://www.bro.org/sphinx-git/frameworks/intel.html>`_.

|Admin page for add a intel|

 * indicator   indicator_type   meta.source.  meta.desc   meta.url


Page to add a Critical Stack client on a Bro instance :
-------------------------------------------------------

`Critical Stack client <https://criticalstack.zendesk.com/hc/en-us/articles/203408139-Full-Documentation-all-the-things->`_.

|Admin page for add a criticalstack|

 * API Key of your Sensor.
 * Give a crontab for planning pull of intel from feeds.
 * Select the Bro instance to apply.
