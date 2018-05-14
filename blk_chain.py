"""
Naive block chain implementation, the methods I use for encoding and signature is very unsafe!
"""
import datetime
import hashlib
from Crypto import Random
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
from base64 import (
    b64encode,
    b64decode,
)
# import os
# import M2Crypto

# random_func = Random.new().read
# M2Crypto.Rand.rand_seed(os.urandom(1024))

class Block:
    def __init__(self, previousHash):
        self.previousHash = previousHash
        # self.data = data
        self.nonce = 0
        self.timeStamp = datetime.datetime.now()
        # a merkle tree
        self.merkle_root = None
        # a list of Transaction
        self.transactions = list()
        # make sure we already set all the value it needs
        self.hash = self.calculate_hash()
    # Calculate the hash
    def calculate_hash(self):
        return \
        get_hash(self.previousHash+str(self.timeStamp)+str(self.nonce)+self.merkle_root)
        
    def mine_block(self, difficulty):
        self.merkle_root = get_Merkle_root(self.transactions)
        target = ''
        for i in range(difficulty):
            target += '0'
        print "Mining Block.................."
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print "Block Mined!!! : " + self.hash
    
    def add_transaction(self, transaction):
        if transaction == None:
            return False
        if self.previousHash != '0':
            if transaction.process_transaction() != True:
                print "Transaction failed to process. Discarded."
                return False
        self.transactions.append(transaction)
        print "Transaction Successfully added to Block!"
        return True

# consist of blocks, a very vulnarable chain, only the node
# in the beginning store the tail of the chain
class Chain:
    UTXOs = dict()
    difficulty = 5
    minimum_transaction = 0.1
    def __init__(self, block):
        self.block = block
        self.next = None
        self.previous = None
        self.end = self

    # # Append the block to this.next
    # def append_next(self, block_node):
    #     self.next = block_node
    
    # # Apeend this to block.next
    # def append_previous(self, block_node):
    #     block_node.next = self

    def add(self, block_node):
        self.end.next = block_node
        block_node.previous = self.end
        self.end = block_node
    
    def remove_next(self):
        self.next = None
    
    def remove_previous(self):
        self.previous = None

    def remove(self):
        self.remove_next()
        self.remove_previous()


class Wallet:
    def __init__(self):
        self.keys = RSA.generate(1024)
        self.private_key = self.keys.exportKey('DER')
        self.public_key = self.keys.publickey().exportKey('DER')
        
        # UTXO deneotes as unspent transactions(money/coins/whatever)
        # UTXOs is a dictionary as {TransactionOutput.id: TruansactionOutput}
        self.UTXOs = dict()


    def generate_keys(self):
        pass

    # returns balance and stores the UTXO's woned by this wallet in Wallet.UTXOs
    def get_balance(self):
        total = 0
        for item in Chain.UTXOs.keys():
            UTXO = Chain.UTXOs[item]
            if UTXO.isMine(self.public_key):
                self.UTXOs[UTXO.id] = UTXO
                total += UTXO.value
        return total

    # generates and returns a new transaction from this wallet
    def send_funds(self, recipient, value):
        if self.get_balance() < value:
            print "#Not Enough funds to send transaction. Transaction Discarded."
            return None
        inputs = list()
        total = 0
        # loop through the UTXOs belongs this wallet to get enough TransactionInputs
        for item in self.UTXOs.keys():
            UTXO = self.UTXOs[item]
            total += UTXO.value
            inputs.append(TransactionInput(UTXO.id))
            # Calculate to send appropariate amount of money
            if total > value:
                break
        # Generate a new transaction
        new_transaction = Transaction(self.public_key, recipient, value, inputs)
        # Sign the transaction
        new_transaction.apply_rsa_signature(self.private_key)

        # Remove the UTXO this waleet spend(the UTXO that wallet used in this transactions)
        for i in inputs:
            del self.UTXOs[i.transaction_output_ID]
        
        # Return this new transaction
        return new_transaction

class Transaction:
    sequence = 0
    def __init__(self, from_key, to_key, value, inputs):
        # Basic initialization, value is the amount of coins sender
        # wants to transfer to recipient
        self.sender = from_key
        self.recipient = to_key
        self.value = value
        self.transaction_id = None
        # inputs is a list of TransactionInput
        self.inputs = inputs
        # outputs is a list of TransactionOutput
        self.outputs = list()

        # Generate the signature
        self.signature = None

        # The msg we are going to encode
        self.data = str(self.sender) + str(self.recipient)
        # Initialize digest, we just encode the data
        self.digest = SHA256.new()
        self.digest.update(self.data)

    # This will be the ID of our transaction
    def calculate_hash(self):
        Transaction.sequence += 1
        return get_hash(str(self.sender)+str(self.recipient)+str(self.value)+str(Transaction.sequence))

    # This will sign the transaction
    def apply_rsa_signature(self, private_key):
        priv_key_obj = RSA.importKey(private_key)
        # signer is just the owner of the private_key
        signer = PKCS1_v1_5.new(priv_key_obj)
        self.signature = signer.sign(self.digest)
        return self.signature

    # This will verify the signature using the pubkey from sender
    def verify_rsa_signature(self):
        pub_obj = RSA.importKey(self.sender)
        verifier = PKCS1_v1_5.new(pub_obj)
        verified = verifier.verify(self.digest, self.signature)
        return verified
    
    def process_transaction(self):
        # Verify signature
        if self.verify_rsa_signature() == False:
            print "Transaction Signature failed to verify"
            return False
        
        # Gather transaction inputs (make sure they are unspent)
        for i in self.inputs:
            i.UTXO = Chain.UTXOs[i.transaction_output_ID]
        
        # Check if transaction is valid
        if self.get_input_value() < Chain.minimum_transaction:
            print "Transaction Inputs too small: " + self.get_input_value()
            return False
        
        # Generate transaction outputs
        # get value of inputs then the left over
        left_over = self.get_input_value() - self.value
        self.transaction_id = self.calculate_hash()
        # Send the money to the recipient
        self.outputs.append(TransactionOutput(self.recipient, self.value, self.transaction_id))
        # Add the money left to the sender
        self.outputs.append(TransactionOutput(self.sender, left_over, self.transaction_id))

        # add outpus to unspent list
        for o in self.outputs:
            Chain.UTXOs[o.id] = o

        # remove transaction inputs from UTXO lists as spent
        for i in self.inputs:
            if i.UTXO == None:
                continue
            del Chain.UTXOs[i.UTXO.id]
        
        return True

    # returns sum of inputs(UTXOs) values
    def get_input_value(self):
        total = 0
        for i in self.inputs:
            if i.UTXO != None:
                total += i.UTXO.value
        return total

    # returns sum of outputs:
    def gen_outputs_value(self):
        total = 0
        for o in self.outputs:
            total += o.value
        return total
    


class TransactionInput:
    def __init__(self, transaction_output_ID):
        self.transaction_output_ID = transaction_output_ID
        self.UTXO = None

class TransactionOutput:
    def __init__(self, recipient, value, parentTransactionID):
        self.recipient = recipient
        self.value = value
        self.parentTransactionID = parentTransactionID
        self.id = SHA256.new().update(str(recipient)+str(value)+str(parentTransactionID))
    
    def isMine(self, public_key):
        return public_key == self.recipient
    





# print "Hello World"
# Helper method for get hash
shaHash = hashlib.sha256()
def get_hash(input_string):
    shaHash.update(input_string)
    hex_string = shaHash.hexdigest()
    return hex_string

def check_valid(chain):
    iter_node = chain
    iter_hash = chain.block.hash
    print "Checking validation of the chain.............."
    while iter_node.next != None:
        adj_blk_prv_hash = iter_node.next.block.previousHash
        if iter_hash != adj_blk_prv_hash:
            print "Error: Detect unmatched hash in two adjacent blocks."
            break
        iter_node = iter_node.next
        iter_hash = iter_node.block.hash
    print "Finished, block is Valid!"

# Helper method for Merkle tree
""" 
Structure of Merkle Tree:
               Top Hash (Merkle root)
                |    |
               |      |    .............
              |        |
          Hash_01    Hash_12  ...........
            |            |
            |            |
           | |          | |    ............
          |   |        |   |
         |     |      |     |  
      Hash_0    Hash_1     Hash_2   ............
"""
def get_Merkle_root(transactions):
    count = len(transactions)
    previous_tree_layer = list()
    for t in transactions:
        previous_tree_layer.append(t.transaction_id)
    # Just in case count <= 1
    tree_layer = previous_tree_layer
    while count > 1:
        tree_layer = list()
        for i in range(len(previous_tree_layer)-1):
            tree_layer.append(get_hash(previous_tree_layer[i]+previous_tree_layer[i+1]))
        count = len(tree_layer)
        previous_tree_layer = tree_layer
    # Usually top hash should have value except the beginning transactions is empty
    merkle_root = tree_layer[0] if len(tree_layer) == 1 else ""
    return merkle_root

# ============== Block Test =========================
# first_blk = Block('Hi I am the first block.', '0')
# # print "Hash for block 1 : " + first_blk.hash
# second_blk = Block('Hi I am the second block.', first_blk.hash)
# # print "Hash for block 2 : " + second_blk.hash
# third_blk = Block('Hi I am the third block.', second_blk.hash)    
# # print "Hash for block 3 : " + third_blk.hash

# difficulty = 3
# # Initialize the blocks
# blk_chain = Chain(first_blk)
# second_node = Chain(second_blk)
# third_node = Chain(third_blk)
# # Proof of work
# first_blk.mine_block(difficulty)
# second_blk.mine_block(difficulty)
# third_blk.mine_block(difficulty)

# blk_chain.add(second_node)
# blk_chain.add(third_node)

# iter_node = blk_chain
# while iter_node != None:
#     print iter_node.block.hash
#     iter_node = iter_node.next

# check_valid(blk_chain)

# ========================== Wallet Test =====================
# wallet_A = Wallet()
# wallet_B = Wallet()
# transaction1 = Transaction(wallet_A.public_key, wallet_B.public_key, 5, None)
# emsg = transaction1.apply_rsa_signature(wallet_A.private_key)
# print transaction1.verify_rsa_signature()

# ========================== General Test ====================
wallet_A = Wallet()
wallet_B = Wallet()
coinbase = Wallet()
genesis_transaction = Transaction(coinbase.public_key, wallet_A.public_key, 100, None)
genesis_transaction.apply_rsa_signature(coinbase.private_key)
genesis_transaction.transaction_id = '0'
genesis_transaction.outputs.append(TransactionOutput(genesis_transaction.recipient,
                                    genesis_transaction.value, genesis_transaction.transaction_id))

# Add such Unspent Transaction to the UTXOs
Chain.UTXOs[genesis_transaction.outputs[0].id] = genesis_transaction.outputs[0]
# print some information
print "Creating and Mining Genesis block....."
# Generating starting chain node
genesis = Block('0')
genesis.add_transaction(genesis_transaction)
starting_chain = Chain(genesis)
# Testing
block1 = Block(genesis.hash)
print "\nWalletA's balance is: ", wallet_A.get_balance()
print "\nWallet A is Attemping to send funds (40) to WalletB ..."
block1.add_transaction(wallet_A.send_funds(wallet_B.public_key, 40))