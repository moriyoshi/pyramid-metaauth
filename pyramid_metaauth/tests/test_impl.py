import pytest
import mock
from pyramid.renderers import JSON
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from .dummies import new_dummy_authentication_policy, new_dummy_meta_authentication_policy


@pytest.fixture(scope='function')
def target():
    from pyramid_metaauth import AuthenticationPolicyCombo
    return AuthenticationPolicyCombo


def none_or_str(s):
    if s is not None:
        return str(s)
    else:
        return None


@pytest.fixture(scope='function')
def config(target):
    def view(context, request):
        return {
            'authenticated_userid': none_or_str(request.authenticated_userid),
            'unauthenticated_userid': none_or_str(request.unauthenticated_userid),
            'effective_principals': request.effective_principals,
            }
    config = Configurator(settings={})
    config.add_renderer('json', JSON())
    config.add_route('test', '/')
    config.add_view(view, route_name='test', renderer='json')
    return config


@pytest.fixture(scope='function')
def h(config):
    from webtest import TestApp
    return TestApp(config.make_wsgi_app())


def test_impl_no_policies_no_meta(config, h, target):
    config.set_authentication_policy(target(policies=[]))
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] is None
    assert resp_json['unauthenticated_userid'] is None
    assert resp_json['effective_principals'] == []


def test_impl_not_authenticated_no_meta(config, h, target):
    dummy = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa')
        )
    config.set_authentication_policy(target(policies=[dummy]))
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] is None
    assert resp_json['unauthenticated_userid'] is None 
    assert resp_json['effective_principals'] == []
    assert dummy.authenticated_userid.called
    assert dummy.unauthenticated_userid.called
    assert dummy.effective_principals.called


def test_impl_authenticated_no_meta(config, h, target):
    dummy = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    config.set_authentication_policy(target(policies=[dummy]))
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] is None
    assert resp_json['unauthenticated_userid'] is None
    assert resp_json['effective_principals'] == []
    assert dummy.authenticated_userid.called
    assert dummy.unauthenticated_userid.called
    assert dummy.effective_principals.called


def test_impl_no_policies_meta(config, h, target):
    dummy_meta = new_dummy_meta_authentication_policy()
    config.set_authentication_policy(
        target(
            policies=[],
            meta_authentication_policy=dummy_meta
            )
        )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] is None
    assert resp_json['unauthenticated_userid'] is None
    assert resp_json['effective_principals'] == []
    assert dummy_meta.authenticated_userid.called
    assert dummy_meta.unauthenticated_userid.called
    assert dummy_meta.effective_principals.called


def test_impl_not_authenticated_meta(config, h, target):
    dummy = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa')
        )
    dummy_meta = new_dummy_meta_authentication_policy()
    config.set_authentication_policy(
        target(
            policies=[dummy],
            meta_authentication_policy=dummy_meta
            )
        )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] is None
    assert resp_json['unauthenticated_userid'] is None 
    assert resp_json['effective_principals'] == []
    assert dummy_meta.authenticated_userid.called
    assert dummy_meta.unauthenticated_userid.called
    assert dummy_meta.effective_principals.called


def test_impl_authenticated_meta(config, h, target):
    dummy = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    dummy_meta = new_dummy_meta_authentication_policy()
    config.set_authentication_policy(
        target(
            policies=[dummy],
            meta_authentication_policy=dummy_meta 
            )
        )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] is None
    assert resp_json['unauthenticated_userid'] is None
    assert resp_json['effective_principals'] == []


def test_impl_no_policies_valid_meta(config, h, target):
    dummy_meta = new_dummy_meta_authentication_policy(
        authenticated_userid=mock.Mock(return_value='userid'),
        unauthenticated_userid=mock.Mock(return_value='userid')
        )
    config.set_authentication_policy(
        target(
            policies=[],
            meta_authentication_policy=dummy_meta 
            )
        )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] == 'userid'
    assert resp_json['unauthenticated_userid'] == 'userid'
    assert resp_json['effective_principals'] == []


def test_impl_not_authenticated_valid_meta(config, h, target):
    dummy = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa')
        )
    dummy_meta = new_dummy_meta_authentication_policy(
        authenticated_userid=mock.Mock(return_value='userid'),
        unauthenticated_userid=mock.Mock(return_value='userid')
        )
    config.set_authentication_policy(
        target(
            policies=[dummy],
            meta_authentication_policy=dummy_meta 
            )
        )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] == 'userid'
    assert resp_json['unauthenticated_userid'] == 'userid'
    assert resp_json['effective_principals'] == []


def test_impl_authenticated_valid_meta(config, h, target):
    dummy = new_dummy_authentication_policy(
        unauthenticated_userid=mock.Mock(return_value='aaa'),
        authenticated_userid=mock.Mock(return_value='aaa')
        )
    dummy_meta = new_dummy_meta_authentication_policy(
        authenticated_userid=mock.Mock(return_value='userid'),
        unauthenticated_userid=mock.Mock(return_value='userid')
        )
    config.set_authentication_policy(
        target(
            policies=[dummy],
            meta_authentication_policy=dummy_meta 
            )
        )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()
    resp = h.get('/')
    resp_json = resp.json
    assert resp_json['authenticated_userid'] == 'userid'
    assert resp_json['unauthenticated_userid'] == 'userid'
    assert resp_json['effective_principals'] == []

