import itertools
from zope.interface import implementer
from .interfaces import IMetaAuthenticationPolicy, IAuthenticationPolicyCombo
from collections import OrderedDict


class AuthenticationPolicyComboBase(object):

    policies = []

    def get_meta_authentication_policy(self, request):
        raise NotImplementedError

    def authenticated_userid(self, request):
        policy_userid_pairs = [
            (policy, userid)
            for policy, userid in (
                (policy, policy.authenticated_userid(request))
                for policy in self.policies
                )
            if userid is not None
            ]
        meta_authentication_policy = self.get_meta_authentication_policy(request)
        if meta_authentication_policy is None:
            return None
        else:
            return meta_authentication_policy.authenticated_userid(request, self, policy_userid_pairs)

    def unauthenticated_userid(self, request):
        policy_userid_pairs = [
            (policy, userid)
            for policy, userid in (
                (policy, policy.unauthenticated_userid(request))
                for policy in self.policies
                )
            if userid is not None
            ]
        meta_authentication_policy = self.get_meta_authentication_policy(request)
        if meta_authentication_policy is None:
            return None
        else:
            return meta_authentication_policy.unauthenticated_userid(request, self, policy_userid_pairs)

    def effective_principals(self, request):
        policy_principal_set_pairs = [
            (policy, policy.effective_principals(request))
            for policy in self.policies
            ]
        meta_authentication_policy = self.get_meta_authentication_policy(request)
        if meta_authentication_policy is None:
            return []
        else:
            return meta_authentication_policy.effective_principals(request, self, policy_principal_set_pairs)

    def remember(self, request, userid, **kw):
        meta_authentication_policy = self.get_meta_authentication_policy(request)
        if meta_authentication_policy is None:
            return []
        else:
            return meta_authentication_policy.remember(request, self, userid, **kw)

    def forget(self, request):
        meta_authentication_policy = self.get_meta_authentication_policy(request)
        if meta_authentication_policy is None:
            return []
        else:
            return meta_authentication_policy.forget(request, self)



@implementer(IAuthenticationPolicyCombo)
class AuthenticationPolicyCombo(AuthenticationPolicyComboBase):

    def __init__(self, policies=[], meta_authentication_policy=None):
        self.policies = policies
        self.meta_authentication_policy = meta_authentication_policy

    def get_meta_authentication_policy(self, request):
        return self.meta_authentication_policy


@implementer(IAuthenticationPolicyCombo)
class DynamicAuthenticationPolicyCombo(AuthenticationPolicyComboBase):

    def __init__(self):
        self._policies = OrderedDict()
        self._rev_policies = {}

    def add_policy(self, policy, name=None):
        if policy in self._rev_policies:
            raise ValueError('duplicate policy: {0!r}'.format(policy))
        self._policies.setdefault(name, []).append(policy)
        self._rev_policies[policy] = name

    @property
    def policies(self):
        return itertools.chain.from_iterable(self._policies.values())

    def get_meta_authentication_policy(self, request):
        return request.registry.queryUtility(IMetaAuthenticationPolicy)
