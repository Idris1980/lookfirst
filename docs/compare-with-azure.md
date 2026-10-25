# Comparing a template with Azure

Reading code has a limit. A Bicep or ARM template that says nothing about public access can still give you a storage account anyone can read, because that is Azure's default. `lookfirst try` asks Azure itself what the template would build, and shows what Azure adds to the picture.

```
lookfirst try main.bicep            # free: Azure's what-if preview, nothing is built
lookfirst try --deploy main.bicep   # builds it for real, reads it, deletes it
lookfirst try --cleanup             # removes groups an interrupted run left behind
```

## What happens

1. LookFirst reads the template as usual.
2. It shows which subscription it will use and asks before going on.
3. It creates an empty, temporary resource group, tagged `lookfirst=try` with an expiry time.
4. It asks Azure what the template would create there (`what-if`). This is free and builds nothing.
5. With `--deploy`, it lists the resources, asks again, builds them, and reads what was really built. This can cost money until the group is deleted, which happens right after.
6. It reads Azure's answer with the same rules as the code and writes a report with three parts: what Azure adds (resources the file does not name, and risks that only appear with Azure's defaults), the code on its own, and Azure on its own.
7. It deletes the group, even if you press Ctrl+C.

It uses your own `az login` and needs nothing else installed. Only Bicep and ARM templates for now.

## Other options

- `--location` (default `swedencentral`) and `--subscription` choose where.
- `--parameters` passes a parameters file to the template.
- `--keep` leaves the group in place for you to look at; delete it yourself afterwards.
- `--from-whatif answer.json` compares with a saved answer from `az deployment group what-if --no-pretty-print` instead of asking Azure.
