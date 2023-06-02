"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple
from credential import *
import random

# Optional import
from serialization import jsonpickle




class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TO DO: Complete this function.
        ###############################################
        # Initialize the server informations
        self.users = []

    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        # TO DO: Complete this function.
        ###############################################
        sk , pk = generate_key(subscriptions + ["username"])

        return jsonpickle.encode(pk).encode('utf-8') , jsonpickle.encode(sk).encode('utf-8')
        

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        # Deserialize the server's secret key, public key and issuance request
        server_secret_key = jsonpickle.decode(server_sk)
        server_public_key = jsonpickle.decode(server_pk)
        issuance_request_decoded = jsonpickle.decode(issuance_request)
        
        self.users.append(username)

        #creating issuer_attributes AttributeMap

        L = int((len(server_public_key)- 3) / 2) -1
        issuer_attributes = {i + 1: sub for i, sub in enumerate(subscriptions)}
        issuer_attributes.update({i: "" for i in range(len(subscriptions) + 1, L + 1)})

        #print(server_public_key)

        #create blind signature
        blind_signature = sign_issue_request(server_secret_key,server_public_key, issuance_request_decoded, issuer_attributes)
        
        return jsonpickle.encode(blind_signature)


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        # Deserialize the server public key and signature
        pk = jsonpickle.decode(server_pk)
        disclosure_proof = jsonpickle.decode(signature)

        #verify that revealed attributes and  attributes signed by the disclosure match
        verif = set(list(disclosure_proof[1].values())) == set(revealed_attributes)
    
        return verify_disclosure_proof(pk , disclosure_proof , message) and verif
    
        
    
        


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        # Initialize the users informations
        self.username = None
        self.subscriptions = None
        self.credentials = None
        self.signature = None
        
        # Initialize the server informations
        self.server_pk = None



    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        ###############################################
        # TO DO: Complete this function.
        ###############################################
        # Deserialize the server public key
        server_public_key = jsonpickle.decode(server_pk)
        
        # Define the client and server informations
        self.username = username
        self.subscriptions = subscriptions
        self.secret_key = G1.order().random()

        user_attributes = {0: str(self.secret_key)}
        
        # Create the issuance request with the public key and the user attributes (username and subscriptions).
        issue_request, state = create_issue_request(server_public_key, user_attributes)

        return jsonpickle.encode(issue_request) , state
        
        


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        # TO DO: Complete this function.
        ###############################################
        # Deserialize the server public key and signature
        server_public_key = jsonpickle.decode(server_pk)
        response = jsonpickle.decode(server_response)
        
        # Get the credentials (contains credentials and signature in tuple)  
        credentials = obtain_credential(server_public_key, response, private_state)
        
        return jsonpickle.encode(credentials)
        
        


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        server_public_key = jsonpickle.decode(server_pk)
        creds , signature = jsonpickle.decode(credentials)
        
        hidden_attributes = [cred for cred in creds if cred not in types]

        disclosure_proof = create_disclosure_proof(server_public_key, (creds, signature), hidden_attributes, message)
        
        return jsonpickle.encode(disclosure_proof)
        
