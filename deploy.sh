#!/bin/sh
jekyll build &&
gsutil -m rsync -d -r ./_site gs://static.ctf.rip