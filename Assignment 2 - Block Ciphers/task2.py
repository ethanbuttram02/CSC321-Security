# package imports
import random as rand
from Crypto.Cipher import AES
import secrets
import urllib.parse  # import for URL encoding/decoding

# generate key and IV
key = secrets.token_bytes(16)  # create a random 16-byte key
IV = secrets.token_bytes(16)   # create a random 16-byte initialization vector

# constants for our program
HEADER_SIZE = 54  # change this to 138 if it doesn't work
BLOCK_SIZE = 16   # block size for AES encryption is 16 bytes

def pad_text(data, BLOCK_SIZE):
    # convert string to bytes if it's not already
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    how_much_to_pad = BLOCK_SIZE - (len(data) % BLOCK_SIZE)  # calculate padding needed
    block_to_add_value = bytes([how_much_to_pad])   # make the byte have the value of how much to add
    padded_data = data   # store the current data
    
    # add the padding bytes
    while how_much_to_pad > 0:  # add same byte multiple times until reaching block size
        padded_data += block_to_add_value
        how_much_to_pad -= 1
    return padded_data

def XOR(block1, block2):
    # helper function to XOR two blocks of bytes together
    XORed_block = bytes([b1 ^ b2 for b1, b2 in zip(block1, block2)])
    return XORed_block

def CBC_encrypt(padded_data, key, IV):
    # implement CBC mode encryption using ECB as building block
    cipher = AES.new(key, AES.MODE_ECB)  # initialize the encrypter with key in ECB mode
    encrypted = bytes()  # empty bytes object to store encrypted data
    prev_block = IV      # start with the initialization vector
    
    i = 0
    while i < len(padded_data):  # process data in 16-byte blocks
        block = padded_data[i:i + 16]  # get current block of plaintext
        XORed_block = XOR(block, prev_block)  # XOR with previous ciphertext block or IV
        encrypted_block = cipher.encrypt(XORed_block)  # encrypt the XORed block
        encrypted += encrypted_block  # add to encrypted output
        prev_block = encrypted_block  # update previous block for next iteration
        i += 16  # move to next block
    return encrypted

def CBC_decrypt(encrypted_data, key, IV):
    # implement CBC mode decryption using ECB as building block
    cipher = AES.new(key, AES.MODE_ECB)  # initialize the decrypter with key in ECB mode
    decrypted = bytes()  # empty bytes object to store decrypted data
    prev_block = IV      # start with the initialization vector
   
    i = 0
    while i < len(encrypted_data):  # process data in 16-byte blocks
        encrypted_block = encrypted_data[i:i + 16]  # get current encrypted block
        decrypted_block_xored = cipher.decrypt(encrypted_block)  # decrypt the block 
        decrypted_block = XOR(decrypted_block_xored, prev_block)  # XOR with previous block
        decrypted += decrypted_block  # add to decrypted output
        prev_block = encrypted_block  # update previous block for next iteration
        i += 16  # move to next block
   
    return decrypted

def unpad(padded_data):
    # remove PKCS#7 padding from decrypted data
    padding_length = padded_data[-1]  # last byte indicates padding length
    return padded_data[:-padding_length]  # remove padding bytes

def submit():
    # prepare and encrypt user input
    userid = 456
    sessionid = 31337
    inputStr = input("enter your stuff here: ")  # get user input
    
    # format the input string with user and session IDs
    formatted_str = "userid=" + str(userid) + ";userdata=" + inputStr + ";sessionid=" + str(sessionid)
    
    # url encode non-alphanumeric characters in the input
    encoded_input = urllib.parse.quote(formatted_str, safe='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    
    # encrypt the padded input
    padded_str = pad_text(encoded_input, BLOCK_SIZE)  # apply padding
    encrypted_str = CBC_encrypt(padded_str, key, IV)  # encrypt with CBC mode
    return encrypted_str

def verify(cipherText):
    # decrypt and verify the ciphertext
    plainText = CBC_decrypt(cipherText, key, IV)  # decrypt with CBC mode
    unpadded_text = unpad(plainText).decode('utf-8')  # remove padding and convert to string
    
    # decode the URL encoded text
    decoded_text = urllib.parse.unquote(unpadded_text)
    
    return decoded_text

def main():
    # main function to run the program
    cipherText = submit()  # get and encrypt user input
    plainText = verify(cipherText)  # decrypt the ciphertext
    print(plainText)  # display the result

if __name__ == '__main__':
    main()  # run the main function if script is executed directly