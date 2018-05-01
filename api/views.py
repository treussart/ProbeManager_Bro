import logging

from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from bro.api.serializers import ConfigurationSerializer, BroSerializer, SignatureBroSerializer, ScriptBroSerializer, \
    RuleSetBroSerializer, IntelSerializer, CriticalStackSerializer, BroUpdateSerializer
from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro, Intel, CriticalStack


logger = logging.getLogger(__name__)


class ConfigurationViewSet(viewsets.ModelViewSet):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer


class BroViewSet(viewsets.ModelViewSet):
    queryset = Bro.objects.all()
    serializer_class = BroSerializer


class SignatureBroViewSet(viewsets.ModelViewSet):
    queryset = SignatureBro.objects.all()
    serializer_class = SignatureBroSerializer


class ScriptBroViewSet(viewsets.ModelViewSet):
    queryset = ScriptBro.objects.all()
    serializer_class = ScriptBroSerializer


class RuleSetBroViewSet(viewsets.ModelViewSet):
    queryset = RuleSetBro.objects.all()
    serializer_class = RuleSetBroSerializer


class IntelViewSet(viewsets.ModelViewSet):
    queryset = Intel.objects.all()
    serializer_class = IntelSerializer


class CriticalStackViewSet(viewsets.ModelViewSet):
    queryset = CriticalStack.objects.all()
    serializer_class = CriticalStackSerializer
