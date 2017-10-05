it is intended that sender and receiver are separate computers
sender and receiver both need a copy of KeyGen.java

instructions:
run keygen.java and input the same 16 character keys on each computers

sender puts a message file in the same directory as sender.java
then they run the sender program and type in the name of the message file
the message file is opened, encrypted, and saved as <messagename>.aescipher
sender.java also creates and saves a hash of KMK as <messagename>.khmac
sender.java also encrypts the symmetric key with their public key

all three of these--hashed kmk, encrypted symmetric key, encrypted message--are sent to receiver

with the transferred files in the same directory in the same directory as receiver.java
run receiver and type in the message name (this should be what sender named their file)
receiver.java checks these over by unencrypting with its private key and comparing the hashes
it recreates the message file sender started with
if the hashes match this indicates that the message did indeed com from the intended sender
