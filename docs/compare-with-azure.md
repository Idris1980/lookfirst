# Comparing a template with Azure or AWS

Reading code has a limit. A Bicep or ARM template that says nothing about public access can still give you a storage account anyone can read, because that is Azure's default. A CloudFormation template with a SAM transform creates roles and permissions that are not written in the file. `lookfirst try` asks the cloud itself what the template would build, and shows what the cloud adds to the picture.

```
lookfirst try main.bicep            # Azure: free what-if preview, nothing is built
lookfirst try --deploy main.bicep   # Azure: builds it for real, reads it, deletes it
lookfirst try template.yaml         # AWS: free change set preview, nothing is built
lookfirst try --cleanup             # removes what an interrupted run left behind
```

## Azure (Bicep and ARM)

1. LookFirst reads the template as usual.
2. It shows which subscription it will use and asks before going on.
3. It creates an empty, temporary resource group, tagged `lookfirst=try` with an expiry time.
4. It asks Azure what the template would create there (`what-if`). This is free and builds nothing.
5. With `--deploy`, it lists the resources, asks again, builds them, and reads what was really built. This can cost money until the group is deleted, which happens right after.
6. It reads Azure's answer with the same rules as the code and writes a report with three parts: what Azure adds (resources the file does not name, and risks that only appear with Azure's defaults), the code on its own, and Azure on its own.
7. It deletes the group, even if you press Ctrl+C.

It uses your own `az login` and needs nothing else installed.

Options: `--location` (default `swedencentral`) and `--subscription` choose where, `--parameters` passes a parameters file, `--keep` leaves the group for you to look at, and `--from-whatif answer.json` compares with a saved answer from `az deployment group what-if --no-pretty-print` instead of asking Azure.

## AWS (CloudFormation and SAM)

1. LookFirst reads the template as usual.
2. It shows which AWS account and region it will use and asks before going on.
3. It asks CloudFormation for a change set in a new, empty stack, tagged `lookfirst=try`. A change set for a new stack builds nothing and is free. CloudFormation fills in the parameters and runs transforms such as SAM, so the answer shows every resource the template would really create.
4. It reads the answer with the same rules as the code and writes the same three-part report: what AWS adds, the code on its own, and AWS on its own.
5. It deletes the empty stack, even if you press Ctrl+C.

It uses your own AWS CLI sign-in (`aws login` or `aws configure`). Building for real (`--deploy`) is not available for AWS yet.

Options: `--region` chooses the region (default: the one the AWS CLI is set to), `--parameters params.json` passes parameters in CloudFormation's format, `--keep` leaves the empty stack, and `--from-changeset answer.json` compares with a saved answer from `aws cloudformation describe-change-set --include-property-values --output json` instead of asking AWS. Templates larger than 51,200 bytes must be in S3 for CloudFormation, which `try` does not do yet.
