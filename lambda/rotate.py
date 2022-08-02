# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import boto3
import logging
import os
import json
import re

import ssh
from ssm import SSM

# Top-level element names for JSON structure in SecretString
PUBLIC_KEY ='PublicKey'
PRIVATE_KEY = 'PrivateKey'

# Global environment variables
USERNAME = os.environ['USERNAME']
TARGETS = ""

def lambda_handler(event, context):
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    print(json.dumps(event))
    tag_name = os.environ['TAGNAME']
    tag_value = os.environ['TAGVALUE']

    global TARGETS
    TARGETS = [{"Key": f"tag:{tag_name}", "Values": [tag_value]}]


    print(json.dumps(TARGETS))
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        print(f"Secret {arn} is not enabled for rotation.")
        raise ValueError(f"Secret {arn} is not enabled for rotation.")
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        print(f"Secret version {token} has no stage for rotation of secret {arn}.")
        raise ValueError(
            f"Secret version {token} has no stage for rotation of secret {arn}."
        )

    if "AWSCURRENT" in versions[token]:
        print(f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return
    elif "AWSPENDING" not in versions[token]:
        print(
            f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        )

        raise ValueError(
            f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        )


    if step == "createSecret":
        create_secret(service_client, arn, token, context)

    elif step == "setSecret":
        set_secret(service_client, arn, token, context)

    elif step == "testSecret":
        test_secret(service_client, arn, token, context)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token, context)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token, context):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        print(f"createSecret: Successfully retrieved secret for {arn}.")
    except service_client.exceptions.ResourceNotFoundException:

        # generate a key-pair
        print(f"createSecret: Generating a key pair with token {token}.")
        [priv, pub] = ssh.generate_key_pair(token)

        current_dict[PRIVATE_KEY] = priv
        current_dict[PUBLIC_KEY] = pub

        secret_string = json.dumps(current_dict)

        # save the key-pair
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=secret_string, VersionStages=['AWSPENDING'])
        print(
            f"createSecret: Successfully put secret for ARN {arn} and version {token}."
        )


def set_secret(service_client, arn, token, context):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be set in the service
    pending = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")

    pending_version = pending['VersionId']

    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING")

    ssm = SSM(context, TARGETS, USERNAME)

    print(
        f"setSecret: Invoking Systems Manager to add the new public key with token {pending_version}."
    )

    command_id = ssm.add_public_key(pending_dict[PUBLIC_KEY], pending_version)
    print(
        f"setSecret: Waiting for Systems Manager command {command_id} to complete."
    )

    ssm.wait_completion(command_id)
    print(
        f"setSecret: Systems Manager command {command_id} completed successfully."
    )


def test_secret(service_client, arn, token, context):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    command = 'hostname'
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING")
    print(f"testSecret: getting instance IDs for version {token}")
    ssm = SSM(context, TARGETS, USERNAME)
    ip_addresses = ssm.get_addrs_for_add_key(token)

    print("testSecret: Performing SSH test by invoking command '%s'." % (command))
    ssh.run_command(ip_addresses, USERNAME, pending_dict[PRIVATE_KEY], command)

def finish_secret(service_client, arn, token, context):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)

    new_version = token
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                print(
                    f"finishSecret: Version {version} already marked as AWSCURRENT for {arn}"
                )

                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=new_version, RemoveFromVersionId=current_version)
    print(
        f"finishSecret: Successfully set AWSCURRENT stage to version {new_version} for secret {arn}."
    )


    # after change above:
    prior_version = current_version

    new_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    ssm = SSM(context, TARGETS, USERNAME)

    print(
        f"finishSecret: Invoking Systems Manager to delete the old public key with token {prior_version}."
    )

    command_id = ssm.del_public_key(prior_version)
    print(
        f"finishSecret: Waiting for Systems Manager command {command_id} to complete."
    )

    ssm.wait_completion(command_id)
    print(
        f"finishSecret: Systems Manager command {command_id} completed successfully."
    )

def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

    """

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    # Parse and return the secret JSON string
    return json.loads(plaintext)

