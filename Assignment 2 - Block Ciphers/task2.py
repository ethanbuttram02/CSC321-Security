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

def submit(inputStr = ""):
    # prepare and encrypt user input
    userid = 456
    sessionid = 31337

    if inputStr == "":  # optional parameter for testing the bit flip exploit
        inputStr = input("enter your stuff here: ")  # get user input
    if inputStr==";admin=true;": exit("invalid entry")

    # url encode non-alphanumeric characters in the input
    encoded_input = urllib.parse.quote(inputStr, safe='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    
    # format the input string with user and session IDs
    formatted_str = "userid=" + str(userid) + ";userdata=" + encoded_input + ";sessionid=" + str(sessionid)
    
    # encrypt the padded input
    padded_str = pad_text(formatted_str, BLOCK_SIZE)  # apply padding
    encrypted_str = CBC_encrypt(padded_str, key, IV)  # encrypt with CBC mode
    return encrypted_str

def verify(cipherText):
    # decrypt and verify the ciphertext
    plainText = CBC_decrypt(cipherText, key, IV)  # decrypt with CBC mode
    unpadded_text = unpad(plainText).decode("utf-8", errors="replace")  # remove padding and convert to string
    
    # decode the URL encoded text
    decoded_text = urllib.parse.unquote(unpadded_text)

    return ";admin=true;" in decoded_text

def bitflip():
    """
    Performs a targeted CBC bit-flipping attack to make verify() return true.
    Focuses on changing '%3F' to '%3D' in the URL-encoded string.
    """
    # create a payload with a pattern we can modify
    payload = ";admin?true;"
    
    # get the ciphertext for our payload
    ciphertext = submit(payload)
    
    # create a modifiable copy of the ciphertext
    modified = bytearray(ciphertext)
    
    # calculate the position of 'F' in '%3F' in the formatted string
    # the formatted string is: "userid=456;userdata=%3Badmin%3Ftrue%3B;sessionid=31337"
    
    # in our URL-encoded payload:
    # ';' becomes '%3B' (3 bytes)
    # '?' becomes '%3F' (3 bytes)
    
    # the prefix "userid=456;userdata=" is 20 bytes
    # then "%3B" is 3 bytes, so "admin" starts at byte 23
    # "admin" is 5 bytes, so '%3F' starts at byte 28
    # the 'F' in '%3F' is at position 30
    
    prefix_length = len("userid=456;userdata=")  # 20 bytes
    encoded_semicolon_length = 3  # %3B is 3 bytes
    admin_length = 5  # "admin" is 5 bytes
    
    # position of 'F' in '%3F'
    pos_of_F = prefix_length + encoded_semicolon_length + admin_length + 2  # +2 for %3 in %3F
    
    # calculate which block and position this falls into
    block_size = 16
    block_number = pos_of_F // block_size  # should be 1 or 2 (0-indexed)
    position_in_block = pos_of_F % block_size  # position within that block
    
    # we need to modify the byte in the previous block at the same position
    modify_position = ((block_number - 1) * block_size) + position_in_block
    
    # the ASCII difference between 'F' (70) and 'D' (68) is 2
    # XORing with 2 will change 'F' to 'D', thus changing '%3F' to '%3D'
    if modify_position >= 0 and modify_position < len(modified):
        modified[modify_position] ^= 2
    
    # return the result of verify with the modified ciphertext
    return verify(bytes(modified))

def main():
    # main function to run the program
    cipherText = submit()  # get and encrypt user input
    verification = verify(cipherText)  # decrypt the ciphertext and verify
    print(verification)  # display the result
    print(bitflip())
    
if __name__ == '__main__':
    main()  # run the main function if script is executed directly