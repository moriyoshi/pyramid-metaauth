from zope.interface import implementer
from pyramid.interfaces import IAuthenticationPolicy
from .impl import DynamicAuthenticationPolicyCombo
from .interfaces import IMetaAuthenticationPolicy
from .utils import combine_headers


@implementer(IMetaAuthenticationPolicy)
class ChooseFirstMetaAuthenticationPolicy(object):

    def authenticated_userid(self, request, combo, policy_userid_pairs):
        if policy_userid_pairs:
            return policy_userid_pairs[0][1]
        else:
            return None

    def unauthenticated_userid(self, request, combo, policy_userid_pairs):
        if policy_userid_pairs:
            return policy_userid_pairs[0][1]
        else:
            return None

    def effective_principals(self, request, combo, policy_principal_set_pairs):
        principals = set()
        for _, _principals in policy_principal_set_pairs:
            principals |= set(_principals)
        return list(principals)

    def remember(self, request, combo, userid, **kw):
        headers = []
        for policy in combo.policies:
            headers = combine_headers(headers, policy.remember(userid, **kw))
        return headers

    def forget(self, request, combo):
        headers = []
        for policy in combo.policies:
            headers = combine_headers(headers, policy.forget())
        return headers


class UserIdentity(dict):

    def __init__(self, *args, **kwargs):
        name_resolver = kwargs.pop('_name_resolver')
        super(UserIdentity, self).__init__(*args, **kwargs)
        self.name_resolver = name_resolver

    def __str__(self):
        return '!'.join('{0}:{1}'.format(*pair) for pair in sorted((self.name_resolver(pair[0]), pair[1]) for pair in self.items()))


def default_name_resolver(registry, policy):
    name = None
    impl = registry.getUtility(IAuthenticationPolicy)
    if isinstance(impl, DynamicAuthenticationPolicyCombo):
        name = impl._rev_policies.get(policy)
    if name is None:
        name = repr(policy)
    return name


@implementer(IMetaAuthenticationPolicy)
class CombinedMetaAuthenticationPolicy(object):

    def __init__(self, registry, name_resolver=None):
        self.registry = registry
        if name_resolver is None:
            name_resolver = default_name_resolver
        self.name_resolver = lambda policy: name_resolver(registry, policy)

    def authenticated_userid(self, request, combo, policy_userid_pairs):
        if not policy_userid_pairs:
            return None
        else:
            return UserIdentity(policy_userid_pairs, _name_resolver=self.name_resolver)

    def unauthenticated_userid(self, request, combo, policy_userid_pairs):
        if not policy_userid_pairs:
            return None
        else:
            return UserIdentity(policy_userid_pairs, _name_resolver=self.name_resolver)

    def effective_principals(self, request, combo, policy_principal_set_pairs):
        principals = set()
        for policy, _principals in policy_principal_set_pairs:
            principals.update('{0}:{1}'.format(self.name_resolver(policy), principal) for principal in _principals)
        return list(principals)

    def remember(self, request, combo, userid, **kw):
        assert isinstance(userid, UserIdentity)
        headers = []
        for policy in combo.policies:
            headers = combine_headers(headers, policy.remember(userid[policy], **kw))
        return headers

    def forget(self, request, combo):
        headers = []
        for policy in combo.policies:
            headers = combine_headers(headers, policy.forget())
        return headers
