from pyramid.interfaces import IAuthenticationPolicy, PHASE2_CONFIG
from pyramid.exceptions import ConfigurationError
from .interfaces import IMetaAuthenticationPolicy
from .impl import DynamicAuthenticationPolicyCombo


def includeme(config):
    authn_policy = DynamicAuthenticationPolicyCombo()
    config.set_authentication_policy(authn_policy)

    def add_authentication_policy(config, policy, name=None):
        if name is None:
            name = getattr(policy, '__name__', None)
        if not name:
            raise ConfigurationError('policy has no __name__ attribute and name is not provided to add_authentication_policy() directive')
        def register():
            try:
                authn_policy.add_policy(policy, name=name)
            except ValueError as e:
                raise ConfigurationError(str(e))
            config.registry.registerUtility(policy, IAuthenticationPolicy, name=name)

        intr = config.introspectable(
            'authentication policy', None,
            config.object_description(policy),
            'authentication policy'
            )
        intr['policy'] = repr(policy)
        intr['name'] = name
        config.action((IAuthenticationPolicy, name), register, order=PHASE2_CONFIG,
                    introspectables=(intr,))

    def set_meta_authentication_policy(config, policy):
        def register():
            _policy = config.maybe_dotted(policy)
            config.registry.registerUtility(_policy, IMetaAuthenticationPolicy)

        intr = config.introspectable(
            'meta authentication policy', None,
            config.object_description(policy),
            'meta authentication policy'
            )
        intr['policy'] = repr(policy)
        config.action(IMetaAuthenticationPolicy, register, order=PHASE2_CONFIG,
                    introspectables=(intr,))

    config.add_directive('add_authentication_policy', add_authentication_policy)
    config.add_directive('set_meta_authentication_policy', set_meta_authentication_policy)
