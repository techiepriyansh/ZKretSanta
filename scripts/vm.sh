#!/usr/bin/bash

avalanche-network-runner control start \
--log-level debug \
--endpoint="0.0.0.0:12342" \
--number-of-nodes=1 \
--avalanchego-path ${AVALANCHEGO_EXEC_PATH} \
--plugin-dir ${AVALANCHEGO_PLUGIN_PATH} \
--blockchain-specs '[{"vm_name":"zkretvm","genesis":"zkretvm/genesis.json"}]' \
--global-node-config '{"log-level": "info"}'
