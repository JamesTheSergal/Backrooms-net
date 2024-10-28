# Backrooms-net
A secure node based communications network.
(Work in progress - Once I do my final audit of the code, it will be published)

## What is Backrooms-net?
Backrooms-net is a project that I had envisioned while I was in highschool, but put down since I didn't have enough programming knowlege to pull it off.
Backrooms-net at it's core is meant to accept data from a client, encrypt and ensure a safe route to another client while communicating in a node based network.
I am currently unhappy with the state of Tor, and other companies providing VPNs that ultimately spy on all of your traffic anyways. I am also particularly unhappy
with several central governments spending lots of time and money to track it's citizens and deanonymize services we use.

## Backrooms-net features
- Dual layer full AES and RSA encryption of at rest persistence data
- Hardware identification (Using TPM in the future) to prevent physical data from being compromised
- Zero/No Trust principles (I can trust you as far as I can throw you)
- Node to Node full RSA-4092 encryption of all data with signatures and hash checks
- Variable security levels. Routes can be customized for much higher security, or lower latency. Max level has Onion Routing.
- Hardened against timing attacks. (Work in progress)
- "NPN" (No package necessary) features allowing you to access the network with nothing but HTTP request
- Signature spoofing (We look like an Apache2 server)
- Route investigation and known entity avoiding network routines
- Node network security features

## For developers
I thought a long time about how to make this network as accessable as possible to as many people as possible because I am very passionate about this issue.

So far, all backrooms nodes have their own web server that you can direct GET and POST requests at. In theory, you can use the network with your browser alone to send messages to another client on the network.
However, for the most secure communications when developing an app to use this network the minimum you will need is something to make HTTP requests, and encrypt data (Using RSA) to follow the Backrooms-net communications protocol.

## My vision
I've had this project in my head for a long time. If I can manage to stay motivated long enough, I just want to get this working and help as many people as possible. There is a massively high chance this won't go anywhere.
Hopefully at the minimum someone will find this code useful in some way.

Otherwise, I have a few usecase programs I have ideas for to demonstrate how the network will work.
One is a desktop app similar to discord with an accompanying android app. It will be extremely interesting to see how that works out since your "host" service is technically a "client" or "endpoint" on the network just the same as people using it.
That means, if you didn't want to rely on one person hosting your chat app, you could always just host it yourself.

## Would you like to know more?
Visit the wiki section! :) (Wiki will be populated once code is published. Forgot to mention. Sorry!)
