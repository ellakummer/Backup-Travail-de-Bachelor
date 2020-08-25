# How to run the program : 

1) in src file : make 
2) in 1st terminal : ./server \{port\}
3) in 2nd terminal : ./client \{client\} \{port\}

# Files descriptions: 

KDF_RK.* : implements the key derivation function. 

ratchetEncrypt.* : implements the encryption of the messages. 

ratchetDecrypt.* : implements the decryption of the messages. 

server* : implements the server's side of the exchange. 

client.* : implements the client's side of the exchange. 

common.* : handles errors. 

other files : from SABER https://github.com/KULeuven-COSIC/SABER/tree/master/Reference_C

