from rest_framework import serializers

from bro.models import Configuration, Bro, SignatureBro, ScriptBro, RuleSetBro, Intel, CriticalStack


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = "__all__"


class BroSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bro
        fields = "__all__"


class BroUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bro
        fields = 'name', 'description', 'installed', 'secure_deployment', 'server', 'rulesets', 'configuration'


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


class IntelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Intel
        fields = "__all__"


class CriticalStackSerializer(serializers.ModelSerializer):
    class Meta:
        model = CriticalStack
        fields = "__all__"
