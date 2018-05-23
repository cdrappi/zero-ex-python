`zero-ex-python` is a python 3.6 tool to trade ERC20 tokens over the [ZeroEx](https://0xproject.com/) protocol

Currently it supports market making via the POST `/order`

# setup instructions
## CODE
(1) clone the repo

```$ git clone git@github.com:cdrappi/zero-ex-python.git; cd zero-ex-python```


(2) make yourself a virtual environment (this will create one called `venv`)

```$ python3.6 -m venv venv```


(3) source this virtual environment

```$ source venv/bin/activate```

(4) install requirements

```pip install -r requirements.txt```


## ETHEREUM

`zero-ex-python` expects you to set two environment variables:

- `ETH_ADDRESS`: your Ethereum address. Should be all lowercase (i.e. not checksummed)

- `ETH_ENCRYPTED_PRIVATE_KEY_PATH`: an absolute filepath to your encrypted private key (JSON). If you instead have a decrypted key, you can encrypt your key using the `Account.encrypt` method in the `eth_account` dependency

When you instantiate a `ZeroEx` object, you can pass it in a `password` to decrypt your private key. If you don't, then it will prompt you to enter your password via command prompt

# Usage
The only method you'll ever want to use is `ZeroEx.post_order`, which will sign an order to whichever relayer you've chosen.
