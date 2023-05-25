from credential import *

import pytest

def test_generate_key():
    attributes = ["1", "2", "3"]
    sk, pk = generate_key(attributes)
    assert sk is not None
    assert pk is not None

def test_sign_and_verify():
    attributes = ["1", "2", "3"]
    sk, pk = generate_key(attributes)
    message = b"Hello, world!"
    signature = sign(sk, [message])
    assert signature is not None
    valid = verify(pk, signature, [message])
    assert valid
    
def test_sign_and_verify_for_longer_messages():
    attributes = ["1", "2", "3", "4"]
    sk, pk = generate_key(attributes)
    msg = b"Here is a"
    msg2 = b"longer test"
    msg3 = b"message"
    msg4 = b"to see if it work"
    signature = sign(sk, [msg, msg2, msg3, msg4])
    assert signature is not None
    valid = verify(pk, signature, [msg, msg2, msg3, msg4])
    assert valid

def test_create_issue_request():
    attributes = ["1", "2", "3", "4", "5"]
    sk, pk = generate_key(attributes)
    
    user_attributes = {1: "2", 2: "3", 3: "4"}
    request, state = create_issue_request(pk, user_attributes)
    assert request is not None
    assert state is not None

def test_sign_issue_request():
    attributes = ["1", "2", "3","4","5"]
    sk, pk = generate_key(attributes)
    user_attributes = {1: "2", 2: "3", 3: "4"}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: "5", 0: "1"}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    assert signature is not None
    assert issuer_attrs is not None

def test_obtain_credential():
    attributes = ["1", "2", "3","4","5"]
    sk, pk = generate_key(attributes)
    user_attributes = {1: "2", 2: "3", 3: "4"}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {0: "1", 4: "5"}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    credential = obtain_credential(pk, (signature, issuer_attrs), state)
    assert credential is not None

def test_create_disclosure_proof():
    attributes = ["1", "2", "3","4","5"]
    sk, pk = generate_key(attributes)
    user_attributes = {1: "2", 2: "3", 3: "4"}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: "5", 0: "1"}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    credential = obtain_credential(pk, (signature, issuer_attrs), state)
    hidden_attributes = ["2", "3"]
    message = b"Secret message"
    proof = create_disclosure_proof(pk, credential, hidden_attributes, message)
    assert proof is not None

def test_verify_disclosure_proof():
    attributes = ["1", "2", "3","4","5"]
    sk, pk = generate_key(attributes)
    user_attributes = {1: "2", 2: "3", 3: "4"}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: "5", 0: "1"}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    credential = obtain_credential(pk, (signature, issuer_attrs), state)
    hidden_attributes = ["2", "3"]
    message = b"Secret message"
    proof = create_disclosure_proof(pk, credential, hidden_attributes, message)
    valid = verify_disclosure_proof(pk, proof, message)
    assert valid

