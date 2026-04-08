mkdir tests/test_hermes
cd tests/test_hermes
pwd
wget https://github.com/informalsystems/hermes/releases/download/v1.13.3/hermes-v1.13.3-x86_64-unknown-linux-gnu.tar.gz
tar xzvf hermes-v1.13.3-x86_64-unknown-linux-gnu.tar.gz
ls
cd ../..
pwd
python3 src/main.py binary -b /home/runner/work/binsmasher/binsmasher/tests/test_hermes/hermes-v1.13.3-x86_64-unknown-linux-gnu/hermes
rm -rf ./tests/test_hermes
ls
