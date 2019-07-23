Init and update CCF submodule

Build:
```
mkdir build
cd build
cmake .. -GNinja
ninja
```

Set up Python venv, start a network:
```
cd build
python3.7 -m venv env
source env/bin/activate
pip install -U -r ../tests/requirements.txt

python ../tests/start_network.py -g ../src/runtime_config/gov.lua --label tess -p libtess
```

Send simple transactions
```
cd build
../src/apps/tess/sample_txs.sh
```
