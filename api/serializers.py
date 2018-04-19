from rest_framework import serializers

from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
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
