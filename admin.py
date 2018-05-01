import json
import logging

from django import forms
from django.conf.urls import url
from django.contrib import admin
from django.contrib import messages
from django.contrib.admin.helpers import ActionForm
from django_celery_beat.models import PeriodicTask

from core.utils import create_deploy_rules_task, create_check_task
from core.utils import generic_import_csv
from .forms import BroChangeForm
from .models import Bro, SignatureBro, ScriptBro, RuleSetBro, Configuration, Intel, CriticalStack

logger = logging.getLogger(__name__)


class MarkedRuleMixin(admin.ModelAdmin):
    def make_enabled(self, request, queryset):
        rows_updated = queryset.update(enabled=True)
        if rows_updated == 1:
            message_bit = "1 rule was"
        else:
            message_bit = "%s rules were" % rows_updated
        self.message_user(request, "%s successfully marked as enabled." % message_bit)

    def make_disabled(self, request, queryset):
        rows_updated = queryset.update(enabled=False)
        if rows_updated == 1:
            message_bit = "1 rule was"
        else:
            message_bit = "%s rules were" % rows_updated
        self.message_user(request, "%s successfully marked as disabled." % message_bit)

    make_enabled.short_description = "Mark rule as enabled"
    make_disabled.short_description = "Mark rule as disabled"


class RuleSetBroAdmin(admin.ModelAdmin):
    def test_rules(self, request, obj):
        test = True
        errors = list()
        for ruleset in obj:
            response = ruleset.test_rules()
            if not response['status']:
                test = False
                errors.append(response['errors'])
        if test:
            messages.add_message(request, messages.SUCCESS, "Test rules OK")
        else:
            messages.add_message(request, messages.ERROR, "Test rules failed ! " + str(errors))

    actions = [test_rules]


class BroAdmin(admin.ModelAdmin):
    class Media:
        js = (
            'bro/js/mask-crontab.js',
        )

    def get_form(self, request, obj=None, **kwargs):
        """A ModelAdmin that uses a different form class when adding an object."""
        if obj is None:
            return super(BroAdmin, self).get_form(request, obj, **kwargs)
        else:
            return BroChangeForm

    def save_model(self, request, obj, form, change):
        logger.debug("create scheduled for " + str(obj))
        create_deploy_rules_task(obj)
        create_check_task(obj)
        super().save_model(request, obj, form, change)

    def test_rules(self, request, obj):
        test = True
        errors = list()
        for probe in obj:
            response = probe.test_rules()
            if not response['status']:
                test = False
                errors.append(str(probe) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test rules OK")
        else:
            messages.add_message(request, messages.ERROR, "Test rules failed ! " + str(errors))

    actions = [test_rules]


class ScriptBroAdmin(MarkedRuleMixin, admin.ModelAdmin):
    class Media:
        js = (
            'bro/js/mask-ruleset-field.js',
        )

    def add_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetBro.get_by_id(ruleset_id)
            for script in queryset:
                ruleset.scripts.add(script)
            ruleset.save()

    add_ruleset.short_description = 'Add ruleset'

    def remove_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetBro.get_by_id(ruleset_id)
            for script in queryset:
                ruleset.scripts.remove(script)
            ruleset.save()

    remove_ruleset.short_description = 'Remove ruleset'

    class UpdateActionForm(ActionForm):
        ruleset = forms.ModelChoiceField(queryset=RuleSetBro.get_all(), empty_label="Select a ruleset",
                                         required=False)

    def test_scripts(self, request, obj):
        test = True
        errors = list()
        for script in obj:
            response = script.test_all()
            if not response['status']:
                test = False
                errors.append(str(script) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test scripts OK")
        else:
            messages.add_message(request, messages.ERROR, "Test scripts failed ! " + str(errors))

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        response = obj.test_all()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test script OK")
        else:
            messages.add_message(request, messages.ERROR, "Test script failed ! " + str(response['errors']))

    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetbro__name')
    list_display = ('name', 'enabled')
    action_form = UpdateActionForm
    actions = [MarkedRuleMixin.make_enabled, MarkedRuleMixin.make_disabled,
               add_ruleset, remove_ruleset, test_scripts]


class SignatureBroAdmin(MarkedRuleMixin, admin.ModelAdmin):
    class Media:
        js = (
            'bro/js/mask-ruleset-field.js',
        )

    def add_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetBro.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.add(signature)
            ruleset.save()

    add_ruleset.short_description = 'Add ruleset'

    def remove_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetBro.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.remove(signature)
            ruleset.save()

    remove_ruleset.short_description = 'Remove ruleset'

    class UpdateActionForm(ActionForm):
        ruleset = forms.ModelChoiceField(queryset=RuleSetBro.get_all(), empty_label="Select a ruleset",
                                         required=False)

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for signature in obj:
            response = signature.test_all()
            if not response['status']:
                test = False
                errors.append(str(signature) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        response = obj.test_all()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test signature OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signature failed ! " + str(response['errors']))

    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetbro__name')
    list_display = ('msg', 'enabled')
    action_form = UpdateActionForm
    actions = [MarkedRuleMixin.make_enabled, MarkedRuleMixin.make_disabled,
               add_ruleset, remove_ruleset, test_signatures]


class ConfigurationAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        response = obj.test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))
        super().save_model(request, obj, form, change)

    def test_configurations(self, request, obj):
        test = True
        errors = list()
        for conf in obj:
            response = conf.test()
            if not response['status']:
                test = False
                errors.append(str(conf) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test configurations OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configurations failed ! " + str(errors))

    actions = [test_configurations]


class IntelAdmin(admin.ModelAdmin):

    def get_urls(self):
        urls = super().get_urls()
        my_urls = [url(r'^import_csv/$', self.import_csv, name="import_csv_intel"), ]
        return my_urls + urls

    def import_csv(self, request):
        return generic_import_csv(Intel, request)


class CriticalStackAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    list_display_links = None


admin.site.register(CriticalStack, CriticalStackAdmin)
admin.site.register(Bro, BroAdmin)
admin.site.register(SignatureBro, SignatureBroAdmin)
admin.site.register(ScriptBro, ScriptBroAdmin)
admin.site.register(RuleSetBro, RuleSetBroAdmin)
admin.site.register(Configuration, ConfigurationAdmin)
admin.site.register(Intel, IntelAdmin)
