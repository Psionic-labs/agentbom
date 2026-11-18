#!/bin/sh
cat > .env <<EOF
PORT=3000
EOF
echo "DEBUG=1" >> .env
tar --exclude=.env -czf /tmp/src.tgz .
