from zope.interface import Interface, Attribute
from pyramid.interfaces import IAuthenticationPolicy


class IAuthenticationPolicyCombo(IAuthenticationPolicy):

    policies = Attribute('''Authentication policies associated to this combo''')


class IMetaAuthenticationPolicy(Interface):

    def authenticated_userid(request, combo, policy_userid_pairs):
        pass

    def unauthenticated_userid(request, combo, policy_userid_pairs):
        pass

    def effective_principals(request, combo, policy_principal_set_pairs):
        pass

    def remember(request, combo, userid, **kw):
        pass

    def forget(request, combo):
        pass

