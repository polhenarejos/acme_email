from acme.challenges import ChallengeResponse, Challenge, KeyAuthorizationChallengeResponse, KeyAuthorizationChallenge
import josepy as jose

@ChallengeResponse.register
class EmailReply00Response(KeyAuthorizationChallengeResponse):
    typ = "email-reply-00"

    def simple_verify(self, chall, domain, account_public_key):
        if not self.verify(chall, account_public_key):
            return False
        
        return True


@Challenge.register
class EmailReply00(KeyAuthorizationChallenge):
    response_cls = EmailReply00Response
    typ = response_cls.typ
    from_addr = jose.Field("from")
    
    def validation(self, account_key, **unused_kwargs):
        return self.key_authorization(account_key)
    