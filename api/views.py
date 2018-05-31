import logging

from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import viewsets, mixins, status

from bro.api import serializers
from bro.exceptions import TestRuleFailed
from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro, Intel, CriticalStack


logger = logging.getLogger(__name__)


class ConfigurationViewSet(viewsets.ModelViewSet):
    queryset = Configuration.objects.all()
    serializer_class = serializers.ConfigurationSerializer

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test()
        return Response(response)


class BroViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin,
                 mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = Bro.objects.all()
    serializer_class = serializers.BroSerializer

    def update(self, request, pk=None):
        bro = self.get_object()
        serializer = serializers.BroUpdateSerializer(bro, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        bro = self.get_object()
        serializer = serializers.BroUpdateSerializer(bro, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True)
    def test_rules(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_rules()
        return Response(response)

    @action(detail=True)
    def start(self, request, pk=None):
        obj = self.get_object()
        response = obj.start()
        return Response(response)

    @action(detail=True)
    def stop(self, request, pk=None):
        obj = self.get_object()
        response = obj.stop()
        return Response(response)

    @action(detail=True)
    def restart(self, request, pk=None):
        obj = self.get_object()
        response = obj.restart()
        return Response(response)

    @action(detail=True)
    def reload(self, request, pk=None):
        obj = self.get_object()
        response = obj.reload()
        return Response(response)

    @action(detail=True)
    def status(self, request, pk=None):
        obj = self.get_object()
        response = obj.status()
        return Response({'status': response})

    @action(detail=True)
    def uptime(self, request, pk=None):
        obj = self.get_object()
        response = obj.uptime()
        return Response({'uptime': response})

    @action(detail=True)
    def deploy_rules(self, request, pk=None):
        obj = self.get_object()
        response = obj.deploy_rules()
        return Response(response)

    @action(detail=True)
    def deploy_conf(self, request, pk=None):
        obj = self.get_object()
        response = obj.deploy_conf()
        return Response(response)

    @action(detail=True)
    def install(self, request, pk=None):  # pragma: no cover
        obj = self.get_object()
        try:
            version = request.query_params['version']
            response = obj.install(version=version)
        except KeyError:
            response = obj.install()
        return Response(response)


class SignatureBroViewSet(viewsets.ModelViewSet):
    queryset = SignatureBro.objects.all()
    serializer_class = serializers.SignatureBroSerializer

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_all()
        return Response(response)


class ScriptBroViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin,
                       viewsets.GenericViewSet):
    queryset = ScriptBro.objects.all()
    serializer_class = serializers.ScriptBroSerializer

    def create(self, request):
        try:
            ScriptBro.objects.create(**request.data)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_201_CREATED)

    def update(self, request, pk=None):
        try:
            script = self.get_object()
            serializer = serializers.ScriptBroSerializer(script, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except TestRuleFailed:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            script = self.get_object()
            serializer = serializers.ScriptBroSerializer(script, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except TestRuleFailed:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_all()
        return Response(response)


class RuleSetBroViewSet(viewsets.ModelViewSet):
    queryset = RuleSetBro.objects.all()
    serializer_class = serializers.RuleSetBroSerializer

    @action(detail=True)
    def test_rules(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_rules()
        return Response(response)


class IntelViewSet(viewsets.ModelViewSet):
    queryset = Intel.objects.all()
    serializer_class = serializers.IntelSerializer


class CriticalStackViewSet(viewsets.ModelViewSet):
    queryset = CriticalStack.objects.all()
    serializer_class = serializers.CriticalStackSerializer

    @action(detail=True)
    def pull(self, request, pk=None):
        obj = self.get_object()
        response = obj.deploy()
        return Response(response)

    @action(detail=True)
    def list_feeds(self, request, pk=None):
        obj = self.get_object()
        response = obj.list()
        return Response(response)
