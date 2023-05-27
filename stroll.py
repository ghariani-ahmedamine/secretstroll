"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple
from credential import *
import random

# Optional import
from serialization import jsonpickle

# Type aliases
State = Any


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
        self.secret_key = None
        self.public_key = None
        self.valid_attribute_map = None
        self.public_informations  = None
        
        # Initialize the server account
        self.registered_account =  {}

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
        # Transform the valid attribute list in a map
        attribute_map = {index: element for index, element in enumerate(subscriptions)}
        self.valid_attribute_map = attribute_map
        
        # Generate the server attributes (10 attributes between 0 and 1000)
        server_attributes = []
        for i in range(0, 10):
            server_attributes.append(str(randint(1000)))
        
        # Generate the keys of the server
        sk, pk = generate_key(server_attributes)
        
        # Saving the information of the server
        self.secret_key = sk
        self.public_key = pk
        self.public_informations = (pk, attribute_map)
        
        return self.secret_key.to_bytes(), self.public_informations.to_bytes()

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
        issuance_request = jsonpickle.decode(issuance_request)
        
        # Check that all the user attributes are valid for the server
        for attribute in subscriptions:
            if (attribute not in valid_attribute_map.values()):
                raise ValueError("One of the attributes of the user is not in the valid server attribute.")
        
        # Register the user on the server (saved as UserName -> Subscriptions)
        self.registered_account[username] = subscriptions
        
        # Generate the response
        response = None #TODO (Don't understand what should be)
        
        # Serialize the credential response
        serialized_response = jsonpickle.encode(response)

        return serialized_response


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
        sign = jsonpickle.decode(signature)
    
        # Extract components from the signature
        g_u, prod = sign
    
        # Verify the components of the signature
        g = pk[0]
        C = prod / (g_u ** Bn.from_binary(message))
        PK = pk[1]
            
        # TODO Not sure it's the good way to do it (and the good function to use)
        is_valid_proof = verify_non_interactive_proof(PK, pk, C)
    
        return is_valid_proof


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
        pk = jsonpickle.decode(server_pk)
        
        # Define the client and server informations
        self.username = username
        self.subscriptions = subscriptions
        self.server_pk = pk
        
        # Create the issuance request with the public key and the user attributes (username and subscriptions).
        issueRequest, state = create_issue_request(pk, subscriptions.insert(0, username))
        
        return issueRequest.to_bytes(), state


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
        pk = jsonpickle.decode(server_pk)
        response = jsonpickle.decode(server_response)
        
        # Get the credentials (contains credentials and signature in tuple)  
        credentials, signature = obtain_credential(pk, response, private_state)
        
        # Save the credentials and the signature
        self.credentials = credentials
        self.signature = signature
        
        return credentials.to_bytes


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
        pk = jsonpickle.decode(server_pk)
        cred = jsonpickle.decode(credentials)
        
        raise NotImplementedError
