from django.forms import ModelForm

from .models import Bro


class BroChangeForm(ModelForm):
    class Meta:
        model = Bro
        fields = (
                  'description',
                  'installed',
                  'secure_deployment',
                  'server',
                  'rulesets',
                  'configuration'
                  )
