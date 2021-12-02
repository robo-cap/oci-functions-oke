# oci-functions-oke

Example of OKE secret creation/update for docker registry using functions with resource_principal authorization

## Prerequisite

Setup dynamic group to allow resource_principal authorization
1. Create a new Dynamic Group (Identity -> Dynamic Groups)
   ```
   Instances that meet the createria defined by all of these rules will be included in the dynamic group.
   resource.type = 'fnfunc'
   resource.compartment.id = '<compartment's OCID of the function>'
   ```
2. Create policy for Dynamic Group (Identity -> Policies) 
   Select compartment where function resides
   Allow dynamic-group <function-dynamic-group> to use cluster-family in compartment <compartment-namef for OKE cluster>
   

## Deployment

1. Create an Application in OCI and go through steps 1-7 in "Getting Started" guide
2. Execute commands
```
fn init --runtime python oke-func
cd oke-func
```
3. Replace file func.py and add Dockerfile and requirements.txt
4. Deploy the function using command fn -v deploy --app <app-name>

## Invoke Function

```
echo -n '{"secret_name":"docker-auth","namespace":"default","user":"registry-user","passwd":"registry-pass","registry":"registry URL","cluster_id":"cluster-ocid","region":"OCI region"}' | fn invoke <app-name> oke-func
```

JSON required at function invocation

```
{
  "name":"docker-auth",
  "namespace":"default",
  "user":"registry-user",
  "pass":"registry-pass",
  "registry":"registry URL",
  "cluster_id":"cluster-ocid",
  "region":"OCI region"
}
```

## Check results

```
kubectl get secret <secret-name> --namespace <namespace> -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode
```
