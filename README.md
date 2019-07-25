# OpenSSLPOC
This is to learn OpenSSL
Greetz Amlendra

Install the OpenSSL library, for the ubuntu use the below command.
sudo apt-get install libssl–dev

Before compiling the client and server program you will need a Certificate. You can generate your own certificate using the below command.

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem

Note: Here certificate name is mycert.pem.

Compile the Client : gcc -Wall -o client  Client.c -L/usr/lib -lssl -lcrypto
Run :   ./client <host_name> <port_number>

Compile the Server : gcc -Wall -o server Server.c -L/usr/lib -lssl -lcrypto
Run : sudo ./server <portnum>
  
Server run first, using the below command we will run the server and wait for the client request.

sudo ./server  8081

After that, we will run client using the below command and send the XML request.

./client  127.0.0.1 8081

If the client sends a valid request as per the server then server give a proper response.

Client:
"<Body>
<UserName>aticle</UserName>
<Password>123</Password>
</Body>"

Server Response:

"<Body>
<Name>aticleworld.com</Name>
<year>1.5</year> 
<BlogType>Embedede and c c++</BlogType> 
<Author>amlendra</Author> 
</Body>"

If the client sends an invalid request to the server then server give a response to an “Invalid message”.

Client:
"<Body>
<UserName>amlendra</UserName>
<Password>1235</Password>
</Body>"

Server:
“Invalid Message”
