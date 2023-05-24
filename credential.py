"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

import hashlib
from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.multiplicative.pairing import G1, G2, GT

from petrelic.bn import Bn

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Any
PublicKey = Any
Signature = Any
Attribute = Any
AttributeMap = Any
IssueRequest = Any
State = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

   # pick x and y1, y2, ..., yL
    x = G2.order().random()
    y = [G2.order().random() for _ in range(len(attributes)) ]

    # pick a generator g and g_tilda 
    g = G1.generator()
    g_tilda = G2.generator() 

    # compute X = g^x and X_tilda = g_tilda^x
    X = g ** x 
    X_tilda = g_tilda ** x

    # compute Y_i and Y_tilda_i
    g_to_y_values = [g ** i for i in y]
    g_tilda_to_y_values = [g_tilda ** i for i in y]

    # form pk = (g, Y1 , ..., YL , , g̃, X̃, Ỹ1 , ..., ỸL )
    pk = (g, ) + tuple(g_to_y_values) + tuple(" ") + (g_tilda, X_tilda) + tuple(g_tilda_to_y_values)
   
    # form sk = (x, X, y1, ... ,yL)
    sk = (x,X) + tuple(y)

    return sk, pk
    


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    
    # Pick random generator h 
    h = G1.generator()

    # Convert msgs from bytes to Bn
    bn_msgs = [Bn.from_binary(m) for m in msgs]
    
    # Unpack secret key components
    x,  y = sk[0],  sk[2:]

    # Compute x + sum (yi * mi)
    sum = inner_product(y, tuple(bn_msgs)) # should it be in Zp ??
    sum = x + sum
    
    # Form signature
    Signature = (h , h ** sum)
    return Signature
    
def inner_product(a, b):
    result = Bn(0)
    for i in range(len(b)):
        result += a[i] * b[i]
    return result

def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    
    # Check that sigma1 is not the neutral element of G1
    if signature[0].is_neutral_element() :
        return False

    # Convert msgs from bytes to Bn 
    bn_msgs = [Bn.from_binary(m) for m in msgs]

    if len(pk) % 2 != 0:
        raise ValueError("The size of the public key should be even !")
    key_length = int((len(pk) - 4)/2)
    message_len = len(msgs)
    
    # Unpack public key compenents from pk = (g, Y1 , ..., YL , , g̃, X̃, Ỹ1 , ..., ỸL )
    g, Y, g_tilda, X_tilda, Y_tilda  = pk[0], pk[1:key_length+1], pk[key_length+2], pk[key_length+3], pk[key_length+4:2*key_length+4]
    
    #Compute the product of Yi ** mi
    prod_Yi_mi = G2.neutral_element()

    for i in range(message_len):
        prod_Yi_mi = prod_Yi_mi.mul(Y_tilda[i] ** bn_msgs[i])
    
    # Check equality of the pairing
    return (signature[0].pair(X_tilda.mul(prod_Yi_mi))) == signature[1].pair(g_tilda)
    
#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> Tuple[IssueRequest, State]: 
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    

    # Pick t 
    t = G2.order().random()
    C = pk[0] ** t

    for i in user_attributes:
        if type(C) == type(pk[i + 1] ** user_attributes[i]):
            C = C.mul(pk[i + 1] ** user_attributes[i])
        else:
            C = C.pair(pk[i + 1] ** user_attributes[i])

    PK = zero_knowledge_proof(t, user_attributes, C, pk) # proof to define 

    return (C, PK) , (t, user_attributes)
    
  

def zero_knowledge_proof(t, user_attributes, C, pk):
    """Creates the zero knowledge proof for the user_attributes,given commitment C""" 
    
    # generate random values
    r = G2.order().random()
    s = G2.order().random()
    
    # compute A and B
    A = (pk[0] ** r).pair(pk[-1] ** s)
    B = C.pair(G1.generator()) ** s * (G1.generator() ** r)
    # compute challenge
    c = hashlib.sha256(A.to_binary() + B.to_binary()).digest()
    c = int.from_bytes(c, byteorder='big') % G2.order()
    
    # compute z_r and z_s
    z_r = r
    z_s = s
    for i in user_attributes:
        z_r = (z_r + (c * pk[i + 1])) % G2.order()
        z_s = (z_s + (c * user_attributes[i])) % G2.order()
    
    # return proof
    return (A, B, c, z_r, z_s)


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    # unpack request 
    C, PK = request[0], request[1]


    assert verify_non_interactive_proof(PK, pk, C) # to define 

    
    
    g  = pk[0]
    
    X = sk[1]
    u = G1.order().random()
    prod = X * C
    for i in issuer_attributes:
        prod = prod * (pk[i + 1 ] ** issuer_attributes[i])
    
    prod = prod ** u
    
    signature = (g ** u , prod)
    return signature , issuer_attributes

def verify_non_interactive_proof(proof, pk, C):
    """Verify the non-interactive zero-knowledge proof for the committed attributes in C"""
    
    # unpack proof
    A, B, c, z_r, z_s = proof
    
    # compute A' and B'
    A_prime = (pk[0] ** z_r) * (pk[-1] ** z_s)
    B_prime = (G1.generator() ** z_r) * (C ** z_s)
    
    # compute challenge
    c_prime = hashlib.sha256(A_prime.export() + B_prime.export()).digest()
    c_prime = int.from_bytes(c_prime, byteorder='big') % G2.order()
    
    # check if challenges match
    if c != c_prime:
        return False
    
    # check if A and A' match
    if not A.is_equal(pk[0] ** z_r * pk[-1] ** z_s * A_prime.inverse()):
        return False
    
    # check if B and B' match
    if not B.is_equal(G1.generator() ** z_r * C ** z_s * B_prime.inverse()):
        return False
    
    # proof is valid
    return True


    

def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        state: State # to define
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    # unpack signature
    sig1, sig2, t = response[0][0], response[0][1], state[0]
    
    signature = sig1, ( sig2/(sig1 ** t) )

    # unpack attributes
    issuer_attributes = response[1]
    user_attributes = state[1]

    creds_dic = dict(issuer_attributes)
    creds_dic.update(user_attributes)

    creds = []
    for i in sorted (creds_dic.keys()):
        creds.append(creds_dic[i])

    assert verify(pk, signature, creds)

    return creds, signature    

## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()
