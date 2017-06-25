import pytest
import mock
from pyramid.renderers import JSON
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from .dummies import new_dummy_authentication_policy

def none_or_str(s):
    if s is not None:
        return str(s)
    else:
        return None


@pytest.fixture(scope='function')
def config():
    def view(context, request):
        return {
            'authenticated_userid': none_or_str(request.authenticated_userid),
            'unauthenticated_userid': none_or_str(request.unauthenticated_userid),
            'effective_principals': request.effective_principals,
            }
    config = Configurator(settings={})
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.include('pyramid_metaauth')
    config.add_renderer('json', JSON())
    config.add_route('test', '/')
    config.add_view(view, route_name='test', renderer='json')
    return config


@pytest.fixture(scope='function')
def h(config):
    from webtest import TestApp
    return TestApp(config.make_wsgi_app())


def test_choose_first_meta_authentication_policy_not_authenticated(config, h):
    from ..meta_policies import ChooseFirstMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy()
    authn_policy2 = new_dummy_authentication_policy()
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = ChooseFirstMetaAuthenticationPolicy()
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] is None
    assert resp.json['unauthenticated_userid'] is None
    assert resp.json['effective_principals'] == []


def test_choose_first_meta_authentication_policy_authned_by_first(config, h):
    from ..meta_policies import ChooseFirstMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    authn_policy2 = new_dummy_authentication_policy()
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = ChooseFirstMetaAuthenticationPolicy()
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] == 'aaa'
    assert resp.json['unauthenticated_userid'] == 'aaa'
    assert resp.json['effective_principals'] == []


def test_choose_first_meta_authentication_policy_authned_by_second(config, h):
    from ..meta_policies import ChooseFirstMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy()
    authn_policy2 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='bbb'),
        authenticated_userid=mock.Mock(return_value='bbb')
        )
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = ChooseFirstMetaAuthenticationPolicy()
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] == 'bbb'
    assert resp.json['unauthenticated_userid'] == 'bbb'
    assert resp.json['effective_principals'] == []


def test_choose_first_meta_authentication_policy_authned_by_both(config, h):
    from ..meta_policies import ChooseFirstMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    authn_policy2 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='bbb'),
        authenticated_userid=mock.Mock(return_value='bbb')
        )
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = ChooseFirstMetaAuthenticationPolicy()
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] == 'aaa'
    assert resp.json['unauthenticated_userid'] == 'aaa'
    assert resp.json['effective_principals'] == []


def test_combined_meta_authentication_policy_not_authenticated(config, h):
    from ..meta_policies import CombinedMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy()
    authn_policy2 = new_dummy_authentication_policy()
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = CombinedMetaAuthenticationPolicy(config.registry)
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] is None
    assert resp.json['unauthenticated_userid'] is None
    assert resp.json['effective_principals'] == []


def test_combined_meta_authentication_policy_authned_by_first(config, h):
    from ..meta_policies import CombinedMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    authn_policy2 = new_dummy_authentication_policy()
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = CombinedMetaAuthenticationPolicy(config.registry)
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] == 'pol1:aaa'
    assert resp.json['unauthenticated_userid'] == 'pol1:aaa'
    assert resp.json['effective_principals'] == []


def test_combined_meta_authentication_policy_authned_by_second(config, h):
    from ..meta_policies import CombinedMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy()
    authn_policy2 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='bbb'),
        authenticated_userid=mock.Mock(return_value='bbb')
        )
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = CombinedMetaAuthenticationPolicy(config.registry)
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] == 'pol2:bbb'
    assert resp.json['unauthenticated_userid'] == 'pol2:bbb'
    assert resp.json['effective_principals'] == []


def test_combined_meta_authentication_policy_authned_by_both(config, h):
    from ..meta_policies import CombinedMetaAuthenticationPolicy
    authn_policy1 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    authn_policy2 = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='bbb'),
        authenticated_userid=mock.Mock(return_value='bbb')
        )
    config.add_authentication_policy(authn_policy1, name='pol1')
    config.add_authentication_policy(authn_policy2, name='pol2')
    meta_authn_policy = CombinedMetaAuthenticationPolicy(config.registry)
    config.set_meta_authentication_policy(meta_authn_policy)
    config.commit()
    resp = h.get('/')
    assert resp.json['authenticated_userid'] == 'pol1:aaa!pol2:bbb'
    assert resp.json['unauthenticated_userid'] == 'pol1:aaa!pol2:bbb'
    assert resp.json['effective_principals'] == []

