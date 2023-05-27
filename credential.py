"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use jsonpickle serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

import hashlib
from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.multiplicative.pairing import *

from petrelic.bn import Bn

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Any
PublicKey = Any
Signature = Tuple[G1Element, G1Element]

AttributeMap = dict[int , str]
ZKproof = Tuple [G1Element , dict[int , Bn] , Bn]
IssueRequest = Tuple[G1Element , ZKproof]
State = Tuple[Bn , AttributeMap]
BlindSignature = Tuple[Signature , AttributeMap]
AnonymousCredential = Tuple[List[str ] , Signature]

DisclosureProof = Tuple[Signature , AttributeMap , GTElement]


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[str]
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
    pk = (g, ) + tuple(g_to_y_values) + tuple(" ")  + (g_tilda, X_tilda) + tuple(g_tilda_to_y_values)
    
    # form sk = (x, X, y1, ... ,yL)
    sk = (x,X) + tuple(y)

    return sk, pk
    


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages msgs """
    
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

    Warning: You may need to pass state to the obtain_credential function.
    """
    

    # Pick t 
    t = G2.order().random()
    C = pk[0] ** t

    for i in user_attributes:
     
        C = C.mul(pk[i + 1] ** Bn.from_binary(user_attributes[i].encode()))
        

    PK = zero_knowledge_proof(t, user_attributes, C, pk) # proof to define 

    return (C, PK) , (t, user_attributes)
    
  

def zero_knowledge_proof(t, user_attributes, C, pk):
    """Creates the zero knowledge proof for the user_attributes,given commitment C""" 
    
    # generate random values
    L = len(user_attributes)
    r_t = G1.order().random()
    r_m = {}
    r_m = {i: G1.order().random() for i in user_attributes}

    R = pk[0] ** r_t
    for i in user_attributes:
        R *=  (pk[i+1] ** r_m[i])

    to_hash = str(C) + str(R) + str(pk) 
    c = int(hashlib.sha256(to_hash.encode('utf-8')).hexdigest(), 16)
    c = Bn(c)

    s_m = {}
    for i in r_m:
         s_m[i] = (r_m[i] - c * Bn.from_binary(user_attributes[i].encode())).mod(G1.order())
    s_t = (r_t - c * t).mod(G1.order())  

    return R, s_m, s_t  

        
    
    


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
        prod = prod * (pk[i + 1 ] ** Bn.from_binary(issuer_attributes[i].encode()))
    
    prod = prod ** u
    
    signature = (g ** u , prod)
    return signature , issuer_attributes

def verify_non_interactive_proof(proof, pk, C):
    """Verify the non-interactive zero-knowledge proof for the committed attributes in C"""
    
    R = proof[0]
    s_m = proof[1]
    s_t = proof[2]

    #computing challenge from all public info: public key, commitment and R 
    #doing SHA256 hash of the concat binary of the public info
    to_hash = str(C) + str(R) + str(pk) 
    c = int(hashlib.sha256(to_hash.encode('utf-8')).hexdigest(), 16)
    c = Bn(c)
    
    verif = C ** c
    for i in s_m:
        verif *=  ((pk[i + 1]).pow(s_m[i]))
    verif *= (pk[0]).pow(s_t)

    #checking if verif == R
    return R == verif


    

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
    
    signature = (sig1, ( sig2/(sig1 ** t) ))

    # unpack attributes
    issuer_attributes = response[1]
    user_attributes = state[1]

    attr_dic = dict(issuer_attributes)
    attr_dic.update(user_attributes)

    attributes = []
    for i in sorted (attr_dic.keys()):
        attributes.append(attr_dic[i])
    
    attributes_bytes = [c.encode() for c in attributes]
    assert verify(pk, signature, attributes_bytes)

    return attributes, signature    

## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[str],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    L = len(credential[0])

    r  = G1.order().random() 
    t = G1.order().random()

    signature = credential[1]
    sig_1 , sig_2 = signature[0] , signature[1]
    rand_signature = sig_1 ** r  , (sig_2 * (sig_1 ** t)) ** r
    

    hidden_attr_index_dic = {i: attr for i, attr in enumerate(credential[0]) if attr in hidden_attributes}
    disclosed_attr_index_dic = {i: attr for i, attr in enumerate(credential[0]) if attr not in hidden_attributes}
    
    
    
    proof = showing_protocol_zkp(rand_signature , hidden_attr_index_dic ,pk , message , t )
    
    return   rand_signature, disclosed_attr_index_dic, proof



def showing_protocol_zkp(rand_signature , hidden_attributes , pk  , message , t )  :
    L = int((len(pk) - 4) / 2)
    rand_sig_1  = rand_signature[0] 
    

    R = (rand_sig_1.pair(pk[2 + L])) ** t
    
    for i in hidden_attributes:
        R *= ((rand_sig_1.pair(pk[ L + 4 + i]) ) ** Bn.from_binary(hidden_attributes[i].encode()))

    hash = hashlib.sha256()
    hash.update(message)

    R *= GT.generator() ** Bn.from_binary(hash.digest())

    

    return R




def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    rand_signature , disclosed_attr_index_dic , proof = disclosure_proof[0] , disclosure_proof[1] ,disclosure_proof[2]
    rand_sig_1 = rand_signature[0]
    
    verification = showing_protocol_verify_zkp (proof, pk,  disclosed_attr_index_dic, rand_signature,message)
    return verification and not rand_sig_1.is_neutral_element()

def showing_protocol_verify_zkp (proof, pk  , disclosed_attr, rand_signature,message) :

    L = int((len(pk) - 4) / 2) 
    g, Y, g_tilda, X_tilda, Y_tilda  = pk[0], pk[1:L+1], pk[L+2], pk[L+3], pk[L+4:2*L+4]
    
    rand_sig_1 , rand_sig_2 = rand_signature[0] , rand_signature[1]
    
    
    

    verification = rand_sig_2.pair(g_tilda) / rand_sig_1.pair(X_tilda)
    

    
    for i in disclosed_attr:
        verification *= ((rand_sig_1.pair(Y_tilda[i])) ** (-Bn.from_binary(disclosed_attr[i].encode())))
    
    hash = hashlib.sha256()
    hash.update(message)

    verification *= GT.generator() ** Bn.from_binary(hash.digest())
    print(proof == verification)
    return (proof == verification) 
