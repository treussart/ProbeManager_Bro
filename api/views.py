import logging

from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action

from bro.api import serializers
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


class SignatureBroViewSet(viewsets.ModelViewSet):
    queryset = SignatureBro.objects.all()
    serializer_class = serializers.SignatureBroSerializer

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_all()
        return Response(response)


class ScriptBroViewSet(viewsets.ModelViewSet):
    queryset = ScriptBro.objects.all()
    serializer_class = serializers.ScriptBroSerializer

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
