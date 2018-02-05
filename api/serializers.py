from rest_framework import serializers

from bro.models import ConfBro, Bro, SignatureBro, ScriptBro, RuleSetBro


class ConfBroSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfBro
        fields = "__all__"


class BroSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bro
        fields = "__all__"


class SignatureBroSerializer(serializers.ModelSerializer):
    class Meta:
        model = SignatureBro
        fields = "__all__"


class ScriptBroSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScriptBro
        fields = "__all__"


class RuleSetBroSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleSetBro
        fields = "__all__"
