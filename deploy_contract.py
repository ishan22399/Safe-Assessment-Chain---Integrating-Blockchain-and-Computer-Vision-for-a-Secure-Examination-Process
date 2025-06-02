import json
import os
from web3 import Web3
from solcx import compile_source, install_solc

# Install solc if needed
try:
    install_solc(version='0.8.0')
except Exception as e:
    print(f"Error installing solc: {e}")
    print("Continuing with already installed version...")

# Connect to Ganache
GANACHE_URL = "http://127.0.0.1:7545"
try:
    web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not web3.is_connected():
        raise Exception("Could not connect to Ganache")
except Exception as e:
    print(f"Error connecting to Ganache: {e}")
    exit(1)

# Read the Solidity contract
contract_path = 'i:\\Blockchain\\edi5\\contracts\\ExamContract.sol'
try:
    with open(contract_path, 'r') as file:
        contract_source_code = file.read()
except Exception as e:
    print(f"Error reading contract: {e}")
    exit(1)

# Compile the contract
try:
    compiled_sol = compile_source(
        contract_source_code, 
        output_values=['abi', 'bin'], 
        solc_version='0.8.0'
    )
    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']
except Exception as e:
    print(f"Error compiling contract: {e}")
    exit(1)

# Save ABI to file
try:
    with open('i:\\Blockchain\\edi5\\ExamContractABI.json', 'w') as file:
        json.dump(abi, file)
    print("ABI saved to ExamContractABI.json")
except Exception as e:
    print(f"Error saving ABI: {e}")

# Get account to deploy from
try:
    account = web3.eth.accounts[0]
    private_key = "0xe41cd5ebbccc66a063227409084e2ab523a15361c322f28171db489fbdcea67a"  # Example key, use environment variable in production
except Exception as e:
    print(f"Error getting account: {e}")
    exit(1)

# Create contract instance
try:
    Contract = web3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Build transaction
    construct_txn = Contract.constructor().build_transaction({
        'from': account,
        'nonce': web3.eth.get_transaction_count(account),
        'gas': 3000000,
        'gasPrice': web3.to_wei('50', 'gwei')
    })
    
    # Sign transaction with private key
    signed = web3.eth.account.sign_transaction(construct_txn, private_key=private_key)
    
    # Debug the signed transaction structure
    print(f"Signed transaction object has attributes: {dir(signed)}")
    
    # Try accessing the raw transaction data with proper attribute handling
    if hasattr(signed, 'rawTransaction'):
        raw_tx = signed.rawTransaction
    elif hasattr(signed, 'raw_transaction'):
        raw_tx = signed.raw_transaction
    else:
        # Try to find the attribute containing raw tx data
        for attr in dir(signed):
            if 'raw' in attr.lower() and not attr.startswith('_'):
                raw_tx = getattr(signed, attr)
                print(f"Found raw transaction data in attribute: {attr}")
                break
        else:
            raise AttributeError("Could not find raw transaction data in signed transaction")
    
    # Send transaction and wait for receipt
    tx_hash = web3.eth.send_raw_transaction(raw_tx)
    print(f"Deployment transaction sent: {tx_hash.hex()}")
    
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    
    print(f"Contract deployed to: {contract_address}")
    
    # Save the contract address to a file
    with open('i:\\Blockchain\\edi5\\contract_address.txt', 'w') as file:
        file.write(contract_address)
    print(f"Contract address saved to contract_address.txt")
    
except Exception as e:
    print(f"Error deploying contract: {e}")
    # Print more detailed error information
    import traceback
    print(traceback.format_exc())
    exit(1)
