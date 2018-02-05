from rest_framework import viewsets
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin

from bro.api.serializers import ConfBroSerializer, BroSerializer, SignatureBroSerializer, ScriptBroSerializer, \
    RuleSetBroSerializer
from bro.models import ConfBro, Bro, SignatureBro, ScriptBro, RuleSetBro


class ConfBroViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = ConfBro.objects.all()
    serializer_class = ConfBroSerializer


class BroViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Bro.objects.all()
    serializer_class = BroSerializer


class SignatureBroViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = SignatureBro.objects.all()
    serializer_class = SignatureBroSerializer


class ScriptBroViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = ScriptBro.objects.all()
    serializer_class = ScriptBroSerializer


class RuleSetBroViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = RuleSetBro.objects.all()
    serializer_class = RuleSetBroSerializer
