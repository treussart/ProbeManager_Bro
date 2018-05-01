import json
import logging

from django_celery_beat.models import PeriodicTask, CrontabSchedule
from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from bro.api.serializers import ConfigurationSerializer, BroSerializer, SignatureBroSerializer, ScriptBroSerializer, \
    RuleSetBroSerializer, IntelSerializer, CriticalStackSerializer, BroUpdateSerializer
from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro, Intel, CriticalStack
from core.utils import create_deploy_rules_task, create_check_task

logger = logging.getLogger(__name__)


class ConfigurationViewSet(viewsets.ModelViewSet):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer


class BroViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet):
    queryset = Bro.objects.all()
    serializer_class = BroSerializer

    def create(self, request):
        serializer = BroSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            bro = Bro.get_by_name(request.data['name'])
            logger.debug("create scheduled for " + str(bro))
            create_deploy_rules_task(bro)
            create_check_task(bro)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        bro = self.get_object()
        serializer = BroUpdateSerializer(bro, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        bro = self.get_object()
        serializer = BroUpdateSerializer(bro, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
