import base64
import io
import json
import logging
import os

import oci
import kubernetes
from kubernetes.client.rest import ApiException

from fdk import response

def handler(ctx, data: io.BytesIO = None):
    try:
        req_body = json.loads(data.getvalue())
        secret_name = req_body.get("secret_name")
        namespace = req_body.get("namespace")
        user = req_body.get("user")
        passwd = req_body.get("passwd")
        registry = req_body.get("registry")
        cluster_id = req_body.get("cluster_id")
        region = req_body.get("region")
    except (Exception, ValueError) as ex:
        logging.getLogger().error('error parsing json payload: ' + str(ex))
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": "Invalid JSON payload"}),
            headers={"Content-Type": "application/json"}
        )

    logging.getLogger().info("Successfully parsed JSON data")
    
    try:
        signer = oci.auth.signers.get_resource_principals_signer()
        os.environ['OCI_CLI_AUTH']="resource_principal" #set OCI CLI to use resource_principal authorization
        ce_client = oci.container_engine.ContainerEngineClient(config={'region': region}, signer=signer)
        resp = ce_client.create_kubeconfig(cluster_id)
        with open('/tmp/kubeconfig.txt', 'w') as f:
            f.write(resp.data.text)
    except Exception as ex:
      logging.getLogger().error('An error occured during attempt to generate kubeconfig: ' + str(ex))
      return response.Response(
            ctx, response_data=json.dumps(
                {"message": "Could not generate kubeconfig.txt"}),
            headers={"Content-Type": "application/json"}
        )

    logging.getLogger().info("Successfully generated kubeconfig.txt")

    try:
        auth_decoded = f'{user}:{passwd}'
        auth_decoded_bytes = auth_decoded.encode('ascii')
        base64_auth_message_bytes = base64.b64encode(auth_decoded_bytes)
        base64_auth_message = base64_auth_message_bytes.decode('ascii')

        registry_auth_payload = {
            "auths": { 
                registry: {
                    "username": user,
                    "password": passwd,
                    "auth": base64_auth_message
                }
            }
        }

        secret_data = {
                    ".dockerconfigjson": base64.b64encode(json.dumps(registry_auth_payload).encode()).decode()
        }

        kconfig = kubernetes.config.load_kube_config(config_file='/tmp/kubeconfig.txt')
        v1 = kubernetes.client.CoreV1Api()
        secret = kubernetes.client.V1Secret(
            api_version = 'v1',
            kind = 'Secret',
            type = 'kubernetes.io/dockerconfigjson',
            metadata = {'name': secret_name, 'namespace': namespace},
            data = secret_data
        )
        
        try:
            v1.read_namespaced_secret(name=secret_name, namespace=namespace)
            logging.getLogger().info("Duplicate secret exists. Attempting to delete duplicate")
            v1.delete_namespaced_secret(name=secret_name, namespace=namespace, body=kubernetes.client.V1DeleteOptions())
            logging.getLogger().info("Duplicate secret deleted")
        except ApiException as ex:
            logging.getLogger().info(f"Attempting to renew secret {secret_name} in namespace {namespace}: {ex}")

        v1.create_namespaced_secret(namespace, body=secret)
    except Exception as ex:
        logging.getLogger().error('An error occured during attempt to create secret: ' + str(ex))
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": "An exception occured during secret creation"}),
            headers={"Content-Type": "application/json"}
        )

    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Secret successfuly created"}),
        headers={"Content-Type": "application/json"}
    )
