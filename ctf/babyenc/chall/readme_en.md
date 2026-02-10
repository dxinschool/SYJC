# Notice to Players

baby enc note

## Question attachment

Challenge path: /challenge/chall

Note: Please backup the competition question attachment to your local before repairing, otherwise the original attachment will be overwritten after repairing!

## Players environment

Players can only upload the repair file to the patch directory via SFTP. The key directory functions are as follows:
```bash
challenge #question attachment. The contest question file in this directory will be replaced after repairing
flag      #flag file
patch     #patch directory
```

## Repair steps

1. Use scp to upload the repair file to the specified path
```shell
scp -i /path/to/your_private_key.pem -s -P 22 /path/to/your_patched_file ctf@<server_ip>:/patch/patched
```

2. Create a new version confirmation file
```shell
scp -i /path/to/your_private_key.pem -s -P 22 /path/to/your_version_file ctf@<server_ip>:/patch/version
```
When the following two files exist in the patch directory simultaneously, a patch will be applied:

```bash
patched # file after repair
version # confirm the repair of the signature file
```

Upload the fix file to the /patch directory, rename it to patched, and then create a version file to confirm whether to apply the patch. Wait for about 15 seconds, and the environment will automatically replace the file and clear the patch directory. The replaced file can be viewed under /challenge

## Patch Description

1. Repairs should be made specifically targeting vulnerability points, and functions unrelated to vulnerability points are not allowed to be modified. At the same time, the normal operation of the competition service and the interaction logic should remain unchanged
2. The size of the competition question file must remain unchanged, and modifications are allowed up to a maximum of 30 bytes

