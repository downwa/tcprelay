#!/bin/sh

# To checkout, initially use 'git clone https://github.com/downwa/tcprelay', and subsequently use 'git pull'
# To configure your repository, use:
#    git config --global push.default simple
#    git config --global credential.helper 'cache --timeout=3600'

git add -v --all
git commit -v
git push
