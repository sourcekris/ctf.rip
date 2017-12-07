#!/usr/bin/python

import glob

files = glob.glob("*.md")

searchreplace = {'capturetheswag.blogspot.com':'ctf.rip',
                 }

for f in files:
  content = open(f).read()

  for pattern in searchreplace:
    content = content.replace(pattern, searchreplace[pattern])

  open(f,"w").write(content)

