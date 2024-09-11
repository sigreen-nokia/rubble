#!/bin/bash
mv ./config_sync.py ./backup.py
sed -i '' '/CONFIG_SYNC_ENABLED/d' backup.py
sed -i '' '/config sync not enabled/d' backup.py


