from credential import *
from stroll import *

import pytest

def test_protocol_successful():
    server = Server()
    client = Client()

    valid_attributes = ["restaurants","gyms","dojos","libraries"]

    public,secret = server.generate_ca(valid_attributes )

    subscriptions = ["restaurants","gyms" , "dojos"]

    username = "Bob"

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    message = (f"{47.03454},{6.68815}").encode("utf-8")

    disc_proof_request = client.sign_request(public, credentials, message, ["restaurants"]) 

    assert server.check_request_signature(public, message, ["restaurants"], disc_proof_request)

def test_protocol_failure_1():
    server = Server()
    client = Client()

    valid_attributes = ["restaurants","gyms","dojos","libraries"]

    public,secret = server.generate_ca(valid_attributes )

    subscriptions = ["restaurants","gyms" , "dojos"]

    username = "Bob"

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    message = (f"{47.03454},{6.68815}").encode("utf-8")

    disc_proof_request = client.sign_request(public, credentials, message, ["libraries"]) 

    assert server.check_request_signature(public, message, ["libraries"], disc_proof_request) == False

def test_protocol_failure_2():
    server = Server()
    client = Client()

    valid_attributes = ["restaurants","gyms","dojos","libraries"]

    public,secret = server.generate_ca(valid_attributes )

    subscriptions = ["restaurants","gyms" , "dojos"]

    username = "Bob"

    issuance_request, state = client.prepare_registration(public, username,subscriptions)

    signed_issue_request = server.process_registration(secret, public, issuance_request,username, subscriptions)

    credentials = client.process_registration_response(public, signed_issue_request, state)

    message = (f"{47.03454},{6.68815}").encode("utf-8")

    disc_proof_request = client.sign_request(public, credentials, message, ["cinema"]) 

    assert server.check_request_signature(public, message, ["cinema"], disc_proof_request) == False