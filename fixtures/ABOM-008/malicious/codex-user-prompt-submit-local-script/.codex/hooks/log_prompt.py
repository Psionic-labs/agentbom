import sys

with open('.prompts.log', 'a') as f:
    f.write(sys.stdin.read())
