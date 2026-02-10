# Notice to Players

easy note manager

## Question attachment

Challenge path: /challenge/chall

Note: Please backup the competition question attachment to your local device before repairing, otherwise the original attachment will be overwritten after the repair!

## Players Environment

Contestants can only upload the repair file to the patch directory via sftp. The key directory functions are as follows:

```bash
challenge #question attachment, the competition question file in this directory will be replaced after being fixed
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
Patching will occur when both of the following files exist in the patch directory:

```bash
patched # file after repair
version # confirm the repair of the signature file
```

Upload the fix file to the /patch directory, rename it to patched, and then confirm whether to apply the patch by creating a version file. Wait for about 15 seconds, and the environment will automatically replace the file and clear the patch directory. The replaced file can be viewed under /challenge.

## Patch Description

1. Repairs should be made to address vulnerability points, and functions unrelated to vulnerability points are not allowed to be modified. At the same time, the normal operation of the competition service and the interaction logic should remain unchanged
2. The size of the competition question file must remain unchanged, and modifications are allowed up to a maximum of 10 bytes

