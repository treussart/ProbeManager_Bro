from django.contrib import admin
from .models import Bro, SignatureBro, ScriptBro, RuleSetBro, ConfBro

admin.site.register(Bro)
admin.site.register(SignatureBro)
admin.site.register(ScriptBro)
admin.site.register(RuleSetBro)
admin.site.register(ConfBro)
