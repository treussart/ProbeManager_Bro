from rest_framework import viewsets
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin

from bro.api.serializers import ConfigurationSerializer, BroSerializer, SignatureBroSerializer, ScriptBroSerializer, \
    RuleSetBroSerializer, IntelSerializer, CriticalStackSerializer
from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro, Intel, CriticalStack


class ConfigurationViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer


class BroViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Bro.objects.all()
    serializer_class = BroSerializer


class SignatureBroViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = SignatureBro.objects.all()
    serializer_class = SignatureBroSerializer


class ScriptBroViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = ScriptBro.objects.all()
    serializer_class = ScriptBroSerializer


class RuleSetBroViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = RuleSetBro.objects.all()
    serializer_class = RuleSetBroSerializer


class IntelViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Intel.objects.all()
    serializer_class = IntelSerializer


class CriticalStackViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = CriticalStack.objects.all()
    serializer_class = CriticalStackSerializer
