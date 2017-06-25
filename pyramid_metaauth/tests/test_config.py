import pytest
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from .dummies import new_dummy_authentication_policy


@pytest.fixture(scope='function')
def config():
    config = Configurator(settings={})
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.include('pyramid_metaauth')
    return config


def test_duplicate_policy(config):
    from pyramid.exceptions import ConfigurationError
    config.add_authentication_policy(new_dummy_authentication_policy(), name='x')
    config.add_authentication_policy(new_dummy_authentication_policy(), name='x')
    with pytest.raises(ConfigurationError):
        config.commit()


def test_same_policy_twice(config):
    from pyramid.exceptions import ConfigurationError
    policy = new_dummy_authentication_policy()
    config.add_authentication_policy(policy, name='x')
    config.add_authentication_policy(policy, name='y')
    with pytest.raises(ConfigurationError) as ei:
        config.commit()
    assert 'duplicate' in str(ei.value)
