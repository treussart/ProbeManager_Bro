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


class BroViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
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

    def destroy(self, request, pk=None):
        bro = self.get_object()
        try:
            periodic_task = PeriodicTask.objects.get(
                name=bro.name + "_deploy_rules_" + str(bro.scheduled_rules_deployment_crontab))
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        try:
            periodic_task = PeriodicTask.objects.get(name=bro.name + "_check_task")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        bro.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

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


class CriticalStackViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = CriticalStack.objects.all()
    serializer_class = CriticalStackSerializer

    def create(self, request):
        serializer = CriticalStackSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.debug("create scheduled task for " + str(request.data['api_key']))
            PeriodicTask.objects.create(crontab=CrontabSchedule.objects.get(id=request.data['scheduled_pull']),
                                        name=str(request.data['api_key']) + "_deploy_critical_stack",
                                        task='bro.tasks.deploy_critical_stack',
                                        args=json.dumps([request.data['api_key'], ])
                                        )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        critical_stack = self.get_object()
        try:
            pass
            periodic_task = PeriodicTask.objects.get(
              name=str(critical_stack.api_key) + "_deploy_critical_stack")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        critical_stack.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
