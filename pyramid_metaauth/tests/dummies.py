import mock
from pyramid.interfaces import IAuthenticationPolicy
from zope.interface import directlyProvides
from ..interfaces import IMetaAuthenticationPolicy


def new_dummy_authentication_policy(**kwargs):
    kwargs.setdefault('authenticated_userid', mock.Mock(return_value=None))
    kwargs.setdefault('unauthenticated_userid', mock.Mock(return_value=None))
    kwargs.setdefault('effective_principals', mock.Mock(return_value=[]))
    kwargs.setdefault('remember', mock.Mock(return_value=[]))
    kwargs.setdefault('forget', mock.Mock(return_value=[]))
    retval = mock.Mock(**kwargs)
    directlyProvides(retval, IAuthenticationPolicy)
    return retval


def new_dummy_meta_authentication_policy(**kwargs):
    kwargs.setdefault('authenticated_userid', mock.Mock(return_value=None))
    kwargs.setdefault('unauthenticated_userid', mock.Mock(return_value=None))
    kwargs.setdefault('effective_principals', mock.Mock(return_value=[]))
    kwargs.setdefault('remember', mock.Mock(return_value=[]))
    kwargs.setdefault('forget', mock.Mock(return_value=[]))
    retval = mock.Mock(**kwargs)
    directlyProvides(retval, IMetaAuthenticationPolicy)
    return retval
