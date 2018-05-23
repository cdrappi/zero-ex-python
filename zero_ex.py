""" a simple python wrapper to interact with the 0x protocol

to use this class, set the following three environment variables:
--> "ETH_ADDRESS": your ethereum address
--> "ETH_ENCRYPTED_PRIVATE_KEY_PATH":
        filepath to corresponding encrypted ETH private key (JSON)
"""

import json
import logging
import os
import random
import getpass

import requests
from eth_account import Account
from eth_utils import decode_hex
from web3 import Web3

logger = logging.getLogger(__name__)


class ZeroEx:
    """ class to interface with the 0x protocol """

    relayer_to_api_url = {
        'Radar Relay': 'https://api.radarrelay.com/0x/v0/',
        'ERC dEX': 'https://api.ercdex.com/api/standard/1/v0',
        'Open Relay': 'https://api.openrelay.xyz/v0/',
    }

    exchange_contract_address = '0x12459c951127e0c374ff9105dda097662a027093'
    null_eth_address = '0x0000000000000000000000000000000000000000'

    weth_contract_address = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
    dai_contract_address = '0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359'

    def __init__(self, password=None, relayer='Radar Relay'):
        """
        :param relayer: (str) a key of ZeroEx.relayer_to_api_url
        """
        self.app_url = self.relayer_to_api_url[relayer]
        self._private_key = self._decrypt_private_key(password)

    @staticmethod
    def _decrypt_private_key(password=None):
        """ load encrypted private key from local file
            using a password
            :param password: (str) to decrypt private key file
                if password is None, prompt user to
                decrypt via command line
        """
        with open(os.environ['ETH_ENCRYPTED_PRIVATE_KEY_PATH']) as f:
            keyfile_json = json.load(f)

        if password is None:
            password = getpass.getpass()

        private_key = Account.decrypt(
            keyfile_json=keyfile_json,
            password=password,
        )
        return f'0x{private_key.hex()}'

    def post_order(self,
                   maker_token_address, taker_token_address,
                   maker_token_amount, taker_token_amount,
                   expiration_timestamp,
                   taker_address=null_eth_address):
        """
        :param maker_token_address: (str)
            smart contract address of token that maker wants to BUY
        :param taker_token_address: (str)
            smart contract address of token that maker wants to SELL
        :param maker_token_amount: (int)
            quantity of the token that maker wants to BUY.
            this is in units of the smallest denomination of this token,
            which can be deduced from its "decimals" attribute.
            for many tokens, this value is 18
        :param taker_token_amount: (int)
            quantity of the token that maker wants to SELL
        :param expiration_timestamp: (int) e.g. int(time.time() + 100),
            which would mean 100 seconds from now
        :param taker_address: (str)
            optionally restrict the order to a specific ETH address.
            defaults to the null ETH address,
            which means anyone can take this order

        :return: (requests.Response) 201 on success
        """
        fees_kwargs = {
            'maker_token_address': maker_token_address,
            'taker_token_address': taker_token_address,
            'maker_token_amount': maker_token_amount,
            'taker_token_amount': taker_token_amount,
            'expiration_timestamp': int(expiration_timestamp),
            'taker_address': taker_address,
            'salt': self.generate_pseudo_random_salt()
        }

        fees_response = self.post_fees(**fees_kwargs)
        order_hash = self.get_order_hash_hex(**fees_kwargs, **fees_response)
        message_hash = self.get_message_hash(order_hash)
        elliptic_curve_signature = self.sign_message(
            message_hash=message_hash,
            private_key=self._private_key
        )

        order_dict = {
            'exchangeContractAddress': self.exchange_contract_address,
            'maker': os.environ['ETH_ADDRESS'],
            'taker': fees_kwargs['taker_address'],
            'makerTokenAddress': fees_kwargs['maker_token_address'],
            'takerTokenAddress': fees_kwargs['taker_token_address'],
            'feeRecipient': fees_response['feeRecipient'],
            'makerTokenAmount': str(fees_kwargs['maker_token_amount']),
            'takerTokenAmount': str(fees_kwargs['taker_token_amount']),
            'makerFee': str(fees_response['makerFee']),
            'takerFee': str(fees_response['takerFee']),
            'expirationUnixTimestampSec': str(
                fees_kwargs['expiration_timestamp']
            ),
            'salt': str(fees_kwargs['salt']),
            'ecSignature': elliptic_curve_signature
        }
        response = requests.post(
            url=f'{self.app_url}/order',
            json=order_dict
        )

        if response.status_code != 201:
            try:
                response_json = response.json()
            except:
                response_json = {}
            logger.error(
                f'received invalid response from relayer on post /order '
                f'(status code {response.status_code}).\n'
                f'{json.dumps(response_json, indent=4)}\n'
                f'signature: {json.dumps(elliptic_curve_signature, indent=4)}'
            )
        return response

    def post_fees(self, **kwargs):
        """
        :return: (dict)
            {
                'feeRecipient': str,  # '0xa258b39954cef5cb142fd567a46cddb31a670124'  # noqa
                'makerFee':     int,  # e.g. 100000000000000
                'takerFee':     int,  # e.g. 200000000000000
            }
        """
        response = requests.post(
            url=f'{self.app_url}/fees',
            json={
                'exchangeContractAddress': self.exchange_contract_address,
                'maker': os.environ['ETH_ADDRESS'],
                'taker': kwargs['taker_address'],
                'makerTokenAddress': kwargs['maker_token_address'],
                'takerTokenAddress': kwargs['taker_token_address'],
                'makerTokenAmount': str(kwargs['maker_token_amount']),
                'takerTokenAmount': str(kwargs['taker_token_amount']),
                'expirationUnixTimestampSec': str(kwargs['expiration_timestamp']),
                'salt': str(kwargs['salt'])
            }
        )

        try:
            json_response = response.json()
            return {
                'feeRecipient': json_response['feeRecipient'],
                'makerFee': int(json_response['makerFee']),
                'takerFee': int(json_response['takerFee'])
            }
        except json.decoder.JSONDecodeError as jde:
            logger.error(
                msg=f"threw {jde} when json'ing {response}. "
                    f"defaulting to 0 fee to null address"
            )
            return {
                'feeRecipient': self.null_eth_address,
                'makerFee': 0,
                'takerFee': 0
            }

    def get_order_hash_hex(self, **kwargs):
        """
        calculate order hash from an order

        reference implementation:
        https://github.com/0xProject/0x-monorepo/blob/d4c1b3b0bd26e730ce6687469cdf7283877543e1/packages/0x.js/src/utils/utils.ts#L21  # noqa

        :return: (str) hash of order in hexadecimal, e.g.
            '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
        """
        solidity_sha3_args = [
            {
                'value': self.exchange_contract_address,
                'type': 'address'
            },
            {
                'value': os.environ['ETH_ADDRESS'],
                'type': 'address'
            },
            {
                'value': kwargs['taker_address'],
                'type': 'address'
            },
            {
                'value': kwargs['maker_token_address'],
                'type': 'address'
            },
            {
                'value': kwargs['taker_token_address'],
                'type': 'address'
            },
            {
                'value': kwargs['feeRecipient'],
                'type': 'address'
            },
            {
                'value': kwargs['maker_token_amount'],
                'type': 'uint256',
            },
            {
                'value': kwargs['taker_token_amount'],
                'type': 'uint256',
            },
            {
                'value': kwargs['makerFee'],
                'type': 'uint256',
            },
            {
                'value': kwargs['takerFee'],
                'type': 'uint256',
            },
            {
                'value': kwargs['expiration_timestamp'],
                'type': 'uint256',
            },
            {
                'value': kwargs['salt'],
                'type': 'uint256'
            },
        ]

        return Web3.soliditySha3(
            abi_types=[param['type'] for param in solidity_sha3_args],
            values=[
                (
                    # this function requires checksummed addresses,
                    # but radar relay only accepts lowercase addresses
                    Web3.toChecksumAddress(param['value'])
                    if param['type'] == 'address'
                    else param['value']
                )
                for param in solidity_sha3_args
            ]
        ).hex()

    @classmethod
    def sign_message(cls, message_hash, private_key):
        """ return elliptic curve signature for order hash

        :param message_hash: (str) in hexadecimal
        :param private_key: (str) decrypted private key
        :return: (dict)
            {
                'v': int,  # either 27 or 28
                'r': str,  # 'r' and 's' are in hexadecimal
                's': str,  # and begin with '0x'
            }
        """
        signature = Account.signHash(
            message_hash=message_hash,
            private_key=private_key
        )
        return {
            'v': signature['v'],
            'r': cls.hexify(signature['r']),
            's': cls.hexify(signature['s'])
        }

    @staticmethod
    def get_message_hash(order_hash):
        """ compute SHA3 hash of ETH message prefix and order hash

        :param order_hash: (str) order hash in hexadecimal
        :return: (str) message hash in hexadecimal
        """
        order_hash_bytes = decode_hex(order_hash)
        return Web3.sha3(
            primitive=(
                b"\x19Ethereum Signed Message:\n"
                + str(len(order_hash_bytes)).encode('utf-8')
                + order_hash_bytes
            )
        )

    @staticmethod
    def generate_pseudo_random_salt():
        """ Generates a pseudo-random 256-bit salt

        A salt can be included in a 0x order,
        ensuring that the order generates a unique orderHash
        and will not collide with other outstanding orders
        that are identical in all other parameters

        :return: (int)
        """
        return random.getrandbits(256)


    @staticmethod
    def hexify(base_10_int):
        """ convert base 10 int to hex,
            padding with '0x' prefix and
            initial zeroes if necessary

        :param base_10_int: (int)
        """
        hex_string = hex(base_10_int)[2:]  # remove '0x' prefix
        return f'0x{"0" * (64 - len(hex_string))}{hex_string}'
