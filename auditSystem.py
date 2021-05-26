#!/usr/bin/python3

from hashlib import sha256
import math, random, sys, os
from Crypto import Random
from Crypto.Cipher import AES

def primeSieve(sieveSize):
    sieve = [True] * sieveSize
    sieve[0] = False
    sieve[1] = False
    for i in range(2, int(math.sqrt(sieveSize)) + 1):
        pointer = i * 2
        while pointer < sieveSize:
            sieve[pointer] = False
            pointer += i
    primes = []
    for i in range(sieveSize):
        if sieve[i] == True:
            primes.append(i)
    return primes
    
def rabinMiller(num):
    if(num % 2 == 0 or num < 2):
        return False
    if num == 3:
        return True
    s = num - 1
    t = 0
    while (s % 2 == 0):
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if(i == t-1):
                    return False
                else:
                    i = i + 1
                    v = (v**2) % num
    return True 

L_Primes = primeSieve(100)

def isPrime(num):
    if(num < 2):
        return False
    for prime in L_Primes:
        if(num == prime):
            return True
        if(num%prime == 0):
            return False
    return rabinMiller(num)

def generatePrime(keySize):
    while True:
        num = random.randrange(2**(keySize-1), 2**(keySize))
        if isPrime(num):
            return num

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None  
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def generateKey(keySize):
    p = generatePrime(keySize)
    q = generatePrime(keySize)
    n = p * q
    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break
    d = findModInverse(e, (p-1) * (q-1))
    publicKey = (n, e)
    privateKey = (n, d)
    return (publicKey, privateKey)

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, K):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(K, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, K):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(K, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, keyFilename, outputFilename):
    K = os.urandom(16)
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, K)
    with open(keyFilename, 'rb') as fo:
        key = fo.read()
        n, e = str(key).split(', ')
        n = int(n[2:])
        e = int(e[:-1])
    K11 = int.from_bytes(K , "little")
    K12 = pow(K11, e, n)
    K13 = str(K12)
    K13 = K13.encode()
    with open(outputFilename, 'wb') as fo:
        fo.write(enc)
        fo.write(K13)
        
def decrypt_file(file_name, keyFilename, outputFilename):
    with open(file_name, 'rb') as fo:
        content = fo.read()
    K13 = content[64:]
    ciphertext = content[:64]
    K13 = int(K13.decode())
    with open(keyFilename, 'rb') as fo:
        key = fo.read()
        n, d = str(key).split(', ')
        n = int(n[2:])
        d = int(d[:-1])
    K14 = pow(K13, d, n)
    K15 = K14.to_bytes(16, "little")
    dec = decrypt(ciphertext, K15)
    with open(outputFilename, 'wb') as fo:
        fo.write(dec)

class MerkleNode:
    def __init__(self,data):
        self.data = data
        self.hashVal = sha256(data.encode('utf-8')).hexdigest()

class MerkleTree:
    def buildMerkleTree(self,inputVal,f):
        nodeVal = []
        for i in inputVal:
            nodeVal.append(MerkleNode(i))
        Count = len(nodeVal)
        while Count > 1:
            tempVal = [] 
            if(Count % 2 != 0):
                nodeVal.append(nodeVal[-1])
            for i in range(0,Count,2):
                leftChild = nodeVal[i]
                rightChild = nodeVal[i+1]
                c[leftChild.hashVal] = rightChild.hashVal
                c[rightChild.hashVal] = leftChild.hashVal
                l.append(leftChild.hashVal)
                r.append(rightChild.hashVal)
                f.write(leftChild.data + " : " + leftChild.hashVal + "\n")
                f.write(rightChild.data + " : " + rightChild.hashVal + "\n")
                parent = MerkleNode(leftChild.hashVal + rightChild.hashVal)
                f.write(parent.data + " : " + parent.hashVal + "\n")
                tempVal.append(parent)
            Count = int(Count/2)
            nodeVal = tempVal
        return nodeVal[0].hashVal

    def checkConsistency(self,inputVal1,inputVal2):
        d1 = {}
        d2 = {}
        d3 = {}
        d4 = {}
        out = []

        for i in inputVal1:
            decrypt_file('/home/student/Desktop/Project/' + i + '.cip', '/home/student/Desktop/Project/' + i + '.prv', '/home/student/Desktop/Project/' + i + '.txt')
            f1 = open("//home//student//Desktop//Project//" + i + ".txt", "r")
            content = f1.read(34)
            inputV1.append(content)
        f1.close()
        f = open("//home//student//Desktop//Project//merkle1.tree", "w")
        root1 = m.buildMerkleTree(inputV1,f)
        f.close()

        for i in inputVal2:
            decrypt_file('/home/student/Desktop/Project/' + i + '.cip', '/home/student/Desktop/Project/' + i + '.prv', '/home/student/Desktop/Project/' + i + '.txt')
            f2 = open("//home//student//Desktop//Project//" + i + ".txt", "r")
            content = f2.read(34)
            inputV2.append(content)
        f2.close()
        f = open("//home//student//Desktop//Project//merkle2.tree", "w")
        root2 = m.buildMerkleTree(inputV2,f)
        f.close()
        
        f1 = open("//home//student//Desktop//Project//merkle1.tree", "r")
        f2 = open("//home//student//Desktop//Project//merkle2.tree", "r")
        
        for line1 in f1:
            key1, value1 = line1.split(': ')
            d1[key1] = value1[:-1]
        
        for line2 in f2:
            key2, value2 = line2.split(': ')
            d2[key2] = value2[:-1]
        
        for key,value in d2.items():
            if key in d1:
                d3[key] = value

        if(len(d3) > 0):
            out.append(root1)
            for key,value in d2.items():
                if not key in d1:
                    d4[key] = value
      
            for key, value in d4.items():
                if(MerkleNode(root1 + str(value)).hashVal == root2):
                    out.append(value)
            out.append(root2)
        return out

def checkInclusion(inputVal,d,c):
    check = []
    for key,value in d.items():
        if inputVal in key:
            value = c[value]
            check.append(value)
            inputVal = value
    return check

def verifyAuthenticity(inputVal,check,d,l,r):
    root = check[-1]
    inputVal = MerkleNode(inputVal).hashVal
    print(inputVal)
    for i in range(0, Count-1):
        if inputVal in l:
            inputVal2 = MerkleNode(inputVal + check[i]).hashVal
        elif inputVal in r:
            inputVal2 = MerkleNode(check[i] + inputVal).hashVal
        inputVal = inputVal2
    print(inputVal)

    if(inputVal == root):
        return True
    else:
        return False


if __name__ == "__main__":
    menu = {"1":"Create patient and audit company accounts","2": "Store EHR in the server","3":"Assign audit company with records in the server","4":"Query for patient record and display audit","5":"Verify Authenticity of the record","6":"Check if the records are consistent", "7":"Exit"}

    print("Hi! Decentralized Audit System")
    print("__________________________________")
    
    accounts = {}  
    patients = {}
    m = MerkleTree()
    c ={}
    d = {}
    e = {}  
    l = []
    r = []

    while True: 
        for key,value in menu.items():
            print(key+"  :  "+value)
        print("__________________________________")
        print("Please enter your option")
    
        selection = input()
        
        if(selection == '1'):
            print("Please enter 'patient' if you want to create patient record and 'audit' for audit company")
            ch = input()
            if(ch == 'patient'):

                print("Please enter the patient record name")
                record1 = input()
                if(record1 in patients):
                    print("Patient Record Exists")
                else:
                    print("Please create the password for patient record")
                    pass1 = input()
                    patients[record1] = pass1
                    print("Patient Record created")
                    print(patients)
            elif(ch == 'audit'):

                print("Please enter the audit company name")
                record2 = input()
                if(record2 in accounts):
                    print("Audit Record Exists")
                else:
                    print("Please create the password for audit record")
                    pass2 = input()
                    accounts[record2] = pass2
                    print("Audit Record created")
                    print(accounts)
        
        #patients = {'patient1': '121', 'patient2': '122', 'patient3': '123', 'patient4': '124', 'patient5': '125'}
        #accounts = {'auditc1': '126', 'auditc2': '127'}
        
        if(selection == '2'):
            print("Please select the audit company to create and upload records")
            print("please enter the audit company name")
            ac_n = input()
            for k,v in accounts.items():
                if(ac_n in k):
                    print("Enter the password")
                    ac_p = input()
                    if(v == ac_p):
                        print(k + " is authenticated and can upload the records")
                        print("Please enter the patient record to upload")
                        P_n = input()
                        publicKey, privateKey = generateKey(1024)
                        f = open('%s.publ' %(P_n), 'w')
                        f.write('%s, %s' %(publicKey[0], publicKey[1]))
                        f.close()
                        f = open('%s.prv' %(P_n), 'w')
                        f.write('%s, %s' %(privateKey[0], privateKey[1]))
                        f.close()
                        encrypt_file('/home/student/Desktop/Project/' + P_n + '.txt', '/home/student/Desktop/Project/' + P_n + '.publ', '/home/student/Desktop/Project/' + P_n + '.cip')
                        print(k + " record is succesfully uploaded")
                    else:
                        print("Authentication Failed")
                        break

        if(selection == '3'):  
            print("Please select the audit company to create merkle record")
            print("please enter the audit company name")
            ac_n = input()
            for k,v in accounts.items():
                if(ac_n in k):
                    print("Enter the password")
                    ac_p = input()
                    if(v == ac_p):
                        print(k + " is authenticated and can create the merkle record")
                        print("Please assign patient records to the audit company")
                        A_n = input()
                        len_n = len(A_n)
                        inputVal = A_n[1:len_n-1].split(",")
                        inputVal1 = []
                        for i in inputVal:
                            decrypt_file('/home/student/Desktop/Project/' + i + '.cip', '/home/student/Desktop/Project/' + i + '.prv', '/home/student/Desktop/Project/' + i + '.txt')
                            f1 = open("//home//student//Desktop//Project//" + i + ".txt", "r")
                            content = f1.read(34)
                            inputVal1.append(content)
                        f1.close()
                        f = open("//home//student//Desktop//Project//merkle.tree", "w")
                        root = m.buildMerkleTree(inputVal1,f)
                        c[root] = root
                        print("req:", c)
                        print("left child values", l)
                        print("right child values", r)
                        print("Root of the Merkle Tree: " + root)
                        f.close()

                    else:
                        print("Authentication Failed")
                        break

        #c = {'7550740bb08d0b177881ae6b1042e8ef2f29dc2995a582bf62bba1f065652a22': 'e5835c223bb999eabfafc602bcd8cfd40f33eab7d141b8d7f6f5299b5ce0de38', 'e5835c223bb999eabfafc602bcd8cfd40f33eab7d141b8d7f6f5299b5ce0de38': '7550740bb08d0b177881ae6b1042e8ef2f29dc2995a582bf62bba1f065652a22', '74cbf64c04b6080ee2b1978dbb6c359045b4451b18aaabbfed1f44496cfc6fee': 'bc40fbbf5984866d8850db2a9973c687ee8f4d7f8985cb8cac889f703c04a054', 'bc40fbbf5984866d8850db2a9973c687ee8f4d7f8985cb8cac889f703c04a054': '74cbf64c04b6080ee2b1978dbb6c359045b4451b18aaabbfed1f44496cfc6fee', '369a8c28ee5927481ec34fb896910f3724dd00a1bc32eb51c891bbc2ee4a6995': 'f02018132f462123c856ab2584bc4aeeaff19cf6147819a9020b2646a695a972', 'f02018132f462123c856ab2584bc4aeeaff19cf6147819a9020b2646a695a972': '369a8c28ee5927481ec34fb896910f3724dd00a1bc32eb51c891bbc2ee4a6995', 'ca5d2f76b9de5913b1ed2c80293c8a1ffe97851499b04fffc64432102afc6d38': 'ca5d2f76b9de5913b1ed2c80293c8a1ffe97851499b04fffc64432102afc6d38'}

        if(selection == '4'):
            print("Query for patient records")
            print("Please enter the username of the patient")
            pt_n = input()
            for k,v in patients.items():
                if(pt_n in k):
                    print("Enter the password")
                    pt_p = input()
                    if(v == pt_p):
                        decrypt_file('/home/student/Desktop/Project/' + k + '.cip', '/home/student/Desktop/Project/' + k + '.prv', '/home/student/Desktop/Project/' + k + '.txt')
                        f1 = open("//home//student//Desktop//Project//" + k + ".txt", "r")
                        inVal = f1.read(34)
                        f1.close()
                        f = open("//home//student//Desktop//Project//merkle.tree", "r")
                        for line in f:
                            key, value = line.split(' : ')
                            d[key] = value[:-1]
                        check = checkInclusion(inVal,d,c)
                        if(len(check)> 0):
                            print("The record exist",check)
                            print("The content in the patient record", inVal)
                        else:
                            print("The record does not exist")

        #l = ['7550740bb08d0b177881ae6b1042e8ef2f29dc2995a582bf62bba1f065652a22', '74cbf64c04b6080ee2b1978dbb6c359045b4451b18aaabbfed1f44496cfc6fee', '369a8c28ee5927481ec34fb896910f3724dd00a1bc32eb51c891bbc2ee4a6995']
        #r = ['e5835c223bb999eabfafc602bcd8cfd40f33eab7d141b8d7f6f5299b5ce0de38', 'bc40fbbf5984866d8850db2a9973c687ee8f4d7f8985cb8cac889f703c04a054', 'f02018132f462123c856ab2584bc4aeeaff19cf6147819a9020b2646a695a972']
        #check = ['e5835c223bb999eabfafc602bcd8cfd40f33eab7d141b8d7f6f5299b5ce0de38', 'f02018132f462123c856ab2584bc4aeeaff19cf6147819a9020b2646a695a972', 'ca5d2f76b9de5913b1ed2c80293c8a1ffe97851499b04fffc64432102afc6d38']
        if(selection == '5'):
            print("Verify Authenticity of patient record")
            print("Please enter the username of the patient")
            pt_n = input()
            for k,v in patients.items():
                if(pt_n in k):
                    print("Enter the password")
                    pt_p = input()
                    if(v == pt_p):
                        decrypt_file('/home/student/Desktop/Project/' + k + '.cip', '/home/student/Desktop/Project/' + k + '.prv', '/home/student/Desktop/Project/' + k + '.txt')
                        f1 = open("//home//student//Desktop//Project//" + k + ".txt", "r")
                        inVal1 = f1.read(34)
                        f1.close()
                        f = open("//home//student//Desktop//Project//merkle.tree", "r")
                        for line in f:
                            key, value = line.split(' : ')
                            d[key] = value[:-1]
            
            Count = len(check)
            va = verifyAuthenticity(inVal1,check,d,l,r)
            print(va)

       
        if(selection == '6'):
            print("Check if the audit records are consistent")
            print("please enter the audit company name")
            ac_n1 = input()
            for k,v in accounts.items():
                if(ac_n1 in k):
                    print("Enter the password")
                    ac_p1 = input()
                    if(v == ac_p1):
                        print(k + " is authenticated and can create the merkle record")
                        print("Please assign patient records to the audit company and update list")
                        A_n1 = input()
                        len_n1 = len(A_n1)
                        inputVal1 = A_n1[1:len_n1-1].split(",")
                        inputV1 = []
                        A_n2 = input()
                        len_n2 = len(A_n2)
                        inputVal2 = A_n2[1:len_n2-1].split(",")
                        inputV2 = []
                        check = m.checkConsistency(inputVal1,inputVal2)
                        if len(check) > 0:
                            print("Yes, the records are consistent",check)
                        else:
                            print("No, they are not consistent")

                    else:
                        print("Authentication Failed")
                        break


        if(selection == '7'):
            print("Exit")
            break
