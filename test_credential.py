from credential import *

import pytest

def test_generate_key():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    assert sk is not None
    assert pk is not None

def test_sign_and_verify():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    message = b"Hello, world!"
    signature = sign(sk, [message])
    assert signature is not None
    valid = verify(pk, signature, [message])
    assert valid

def test_create_issue_request():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    user_attributes = {1: 5, 2: 7, 3: 3}
    request, state = create_issue_request(pk, user_attributes)
    assert request is not None
    assert state is not None

def test_sign_issue_request():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    user_attributes = {1: 5, 2: 7, 3: 3}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: 10, 5: 2}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    assert signature is not None
    assert issuer_attrs is not None

def test_obtain_credential():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    user_attributes = {1: 5, 2: 7, 3: 3}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: 10, 5: 2}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    credential = obtain_credential(pk, (signature, issuer_attrs), state)
    assert credential is not None

def test_create_disclosure_proof():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    user_attributes = {1: 5, 2: 7, 3: 3}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: 10, 5: 2}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    credential = obtain_credential(pk, (signature, issuer_attrs), state)
    hidden_attributes = [1, 3]
    message = b"Secret message"
    proof = create_disclosure_proof(pk, credential, hidden_attributes, message)
    assert proof is not None

def test_verify_disclosure_proof():
    attributes = [1, 2, 3]
    sk, pk = generate_key(attributes)
    user_attributes = {1: 5, 2: 7, 3: 3}
    request, state = create_issue_request(pk, user_attributes)
    issuer_attributes = {4: 10, 5: 2}
    signature, issuer_attrs = sign_issue_request(sk, pk, request, issuer_attributes)
    credential = obtain_credential(pk, (signature, issuer_attrs), state)
    hidden_attributes = [1, 3]
    message = b"Secret message"
    proof = create_disclosure_proof(pk, credential, hidden_attributes, message)
    valid = verify_disclosure_proof(pk, proof, message)
    assert valid

