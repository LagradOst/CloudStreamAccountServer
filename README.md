# CloudStreamAccountServer
A simple account server for CloudStream 2

This is the account server code for someone to set up to use logins in the Cloudstream 2 App. The client and server both use encryption, decryption and one time passwords, but I cant assure you that it is 100% secure, I am no expert on this. This code also uses a simple http listener and .txt file and not some advanced sql database. I cant really say that it is very scalable, but should work fine for personal use. 

This code was ment to be run on a windows machine, because linux dosent support the decryption needed. 
