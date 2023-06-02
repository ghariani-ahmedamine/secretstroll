from credential import *
from stroll import *

import pytest

def test_secret_scroll_correct1():
    server = Server()
    client = Client()

    possible_subscriptions = ["restaurant","bar","dojo","gym"]

    publi, secre = server.generate_ca(possible_subscriptions + ["username"])
    public = str(publi.decode('utf-8'))
    secret = str(secre.decode('utf-8'))
    
    username, subscriptions = "Bob", ["bar","gym"]

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    lat,lon = 46.52345, 6.57890

    disc_proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), ["bar","gym"]) 

    assert server.check_request_signature(public, (f"{lat},{lon}").encode("utf-8"), ["bar", "gym"], disc_proof_request)


def test_sign_and_verify1():
    
    attributes = [b"18", b"username"]
    secret, public = generate_key(attributes)
    signature = sign(secret, attributes)
    assert verify(public, signature,attributes)
