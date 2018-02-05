from bro.api import views

urls_to_register = [
    (r'bro/conf', views.ConfBroViewSet),
    (r'bro/bro', views.BroViewSet),
    (r'bro/signature', views.SignatureBroViewSet),
    (r'bro/script', views.ScriptBroViewSet),
    (r'bro/ruleset', views.RuleSetBroViewSet),
]
