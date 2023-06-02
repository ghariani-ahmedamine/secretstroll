import csv
import random
import string
import sys
import time

from credential import *
from stroll import *


def evaluate_keygen():
    sizes = [1, 10, 20, 40]
    num_runs = 100

    # Open the CSV file for writing the measurements
    with open('keygen_measurements.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Size of Subscriptions', 'Time Taken (seconds)', 'Size of pk (bytes)'])

        for size in sizes:
            total_time = 0
            total_pk_size = 0

            for _ in range(num_runs):
                # Generate random subscriptions of the given size
                subscriptions = [''.join(random.choices(string.ascii_letters, k=8)) for _ in range(size)]

                # Measure the time taken by generate_ca
                start_time = time.time()
                sk, pk = generate_key(subscriptions)
                end_time = time.time()

                # Calculate the size of pk
                pk_size = sys.getsizeof(pk)

                # Update the total time and pk size
                total_time += end_time - start_time
                total_pk_size += pk_size

                # Write the measurements to the CSV file
                writer.writerow([size, end_time - start_time, pk_size])

            # Calculate the mean values
            mean_time = total_time / num_runs
            mean_pk_size = total_pk_size / num_runs

            # Print the mean values
            print(f"Size of subscriptions: {size}")
            print(f"Mean time taken: {mean_time} seconds")
            print(f"Mean size of pk: {mean_pk_size} bytes")
            print("------------------------------")

def evaluate_issuance():
    sizes = [1, 10, 20, 40]
    num_runs = 100

    # Open the CSV file for writing the measurements
    with open('issuance_measurements.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Size of Subscriptions', 'Time Taken (seconds)', 'Size of pk (bytes)'])

        for size in sizes:
            total_time = 0
            total_issuance_size = 0

            for _ in range(num_runs):
                # Generate random subscriptions of the given size
                subscriptions = [''.join(random.choices(string.ascii_letters, k=8)) for _ in range(size)]
                server = Server()
                client = Client()
                secret,public = server.generate_ca(subscriptions + ["username"])
                # Measure the time taken for the issuance
                start_time = time.time()
                issuance_request, state = client.prepare_registration(public, "Bob",subscriptions)

                signed_issue_request = server.process_registration(secret, public, issuance_request,"Bob", subscriptions)

                credentials = client.process_registration_response(public, signed_issue_request, state)
                
                end_time = time.time()

                # Calculate the size of issuance request
                issuance_size = sys.getsizeof(issuance_request)

                # Update the total time and pk size
                total_time += end_time - start_time
                total_issuance_size += issuance_size

                # Write the measurements to the CSV file
                writer.writerow([size, end_time - start_time, issuance_size])

            # Calculate the mean values
            mean_time = total_time / num_runs
            mean_issuance_size = total_issuance_size / num_runs

            # Print the mean values
            print(f"Size of issuance: {size}")
            print(f"Mean time taken: {mean_time} seconds")
            print(f"Mean size of issuance: {mean_issuance_size} bytes")
            print("------------------------------")


def evaluate_showing():
    sizes = [1, 10, 20, 40]
    num_runs = 100

    # Open the CSV file for writing the measurements
    with open('showing_measurements.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Size of Subscriptions', 'Time Taken (seconds)', 'Size of request (bytes)'])

        for size in sizes:
            total_time = 0
            total_proof_size = 0

            for _ in range(num_runs):
                # Generate random subscriptions of the given size
                subscriptions = [''.join(random.choices(string.ascii_letters, k=8)) for _ in range(size)]
                server = Server()
                client = Client()
                secret,public = server.generate_ca(subscriptions + ["username"])
                
                proof_request, state = client.prepare_registration(public, "Bob",subscriptions)

                signed_issue_request = server.process_registration(secret, public, proof_request,"Bob", subscriptions)

                
                credentials = client.process_registration_response(public, signed_issue_request, state)
                lat,lon = 46.52345, 6.57890               
                # Measure the time taken for the issuance
                start_time = time.time()
                proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), subscriptions)  
                end_time = time.time()

                # Calculate the size of issuance request
                proof_size = sys.getsizeof(proof_request)

                # Update the total time and pk size
                total_time += end_time - start_time
                total_proof_size += proof_size

                # Write the measurements to the CSV file
                writer.writerow([size, end_time - start_time, proof_size])

            # Calculate the mean values
            mean_time = total_time / num_runs
            mean_proof_size = total_proof_size / num_runs

            # Print the mean values
            print(f"Size of request: {size}")
            print(f"Mean time taken: {mean_time} seconds")
            print(f"Mean size of request: {mean_proof_size} bytes")
            print("------------------------------")

def evaluate_verify():
    sizes = [1, 10, 20, 40]
    num_runs = 100

    # Open the CSV file for writing the measurements
    with open('verify_measurements.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Size of Subscriptions', 'Time Taken (seconds)'])

        for size in sizes:
            total_time = 0
            

            for _ in range(num_runs):
                # Generate random subscriptions of the given size
                subscriptions = [''.join(random.choices(string.ascii_letters, k=8)) for _ in range(size)]
                server = Server()
                client = Client()
                secret,public = server.generate_ca(subscriptions + ["username"])
                
                proof_request, state = client.prepare_registration(public, "Bob",subscriptions)

                signed_issue_request = server.process_registration(secret, public, proof_request,"Bob", subscriptions)

                
                credentials = client.process_registration_response(public, signed_issue_request, state)
                lat,lon = 46.52345, 6.57890               
                
                
                
                proof_request = client.sign_request(public, credentials, (f"{lat},{lon}").encode("utf-8"), subscriptions)  
                start_time = time.time()
                verif = server.check_request_signature(public, (f"{lat},{lon}").encode("utf-8"), subscriptions, disc_proof_request)
                end_time = time.time()

               

                # Update the total time and pk size
                total_time += end_time - start_time
                

                # Write the measurements to the CSV file
                writer.writerow([size, end_time - start_time])

            # Calculate the mean values
            mean_time = total_time / num_runs
            

            # Print the mean values
            print(f"Size of request: {size}")
            print(f"Mean time taken: {mean_time} seconds")
            
            print("------------------------------")

evaluate_keygen()
evaluate_issuance()
evaluate_showing()
evaluate_verify