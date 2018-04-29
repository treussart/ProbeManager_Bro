from bro.api import views

urls_to_register = [
    (r'^bro/configuration', views.ConfigurationViewSet),
    (r'^bro/bro', views.BroViewSet),
    (r'^bro/bro', views.BroUpdateViewSet),
    (r'^bro/signature', views.SignatureBroViewSet),
    (r'^bro/script', views.ScriptBroViewSet),
    (r'^bro/ruleset', views.RuleSetBroViewSet),
    (r'^bro/intel', views.IntelViewSet),
    (r'^bro/criticalstack', views.CriticalStackViewSet),
]
