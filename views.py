from django.shortcuts import render
from django.http import HttpResponseNotFound
from bro.models import Bro
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import logging


logger = logging.getLogger(__name__)


@login_required
def deploy_rules(request, id):
    """
    Deploy the rules of a Bro instance.
    """
    bro = Bro.get_by_id(id)
    if bro is None:
        return HttpResponseNotFound
    else:
        response_tests = bro.test_rules()
        test_pcap = True
        errors = list()
        for pcaptest in bro.pcaptestbro_set.all():
            response_pcap_test = pcaptest.test()
            if not response_pcap_test['status']:
                test_pcap = False
                errors.append(str(pcaptest) + " : " + str(response_pcap_test['errors']))
        if bro.secure_deployment:
            if not response_tests['status']:
                messages.add_message(request, messages.ERROR, 'Error during the rules test')
                return render(request, 'bro/index.html', {'probe': bro})
            elif not test_pcap:
                messages.add_message(request, messages.ERROR, "Test pcap failed ! " + str(errors))
                return render(request, 'bro/index.html', {'probe': bro})
        if response_tests['status']:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(response_tests['errors']))
        if test_pcap:
            messages.add_message(request, messages.SUCCESS, "Test pcap OK")
        else:
            messages.add_message(request, messages.ERROR, "Test pcap failed ! " + str(errors))
        response_deploy_rules = bro.deploy_rules()
        response_reload = bro.reload()
        if response_deploy_rules['result'] == 0 and response_reload['result'] == 0:
            messages.add_message(request, messages.SUCCESS, 'Deployed rules successfully')
        else:
            messages.add_message(request, messages.ERROR, 'Error during the rules deployed')
        return render(request, 'bro/index.html', {'probe': bro})
