# How to run the program : 
\begin{enumerate}
    \item \emph{in src file : }make 
    \item \emph{in 1st terminal : }./server \{port\}
    \item \emph{in 2nd terminal : }./client \{client\} \{port\}
\end{enumerate}
# Files descriptions: 

KDF_RK.* : implements the key derivation function. 

ratchetEncrypt.* : implements the encryption of the messages. 

ratchetDecrypt.* : implements the decryption of the messages. 

server* : implements the server's side of the exchange. 

client.* : implements the client's side of the exchange. 

common.* : handles errors. 

other files : from SABER https://github.com/KULeuven-COSIC/SABER/tree/master/Reference_C

