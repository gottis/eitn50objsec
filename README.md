# EITN50 Project 2
## How to run the different parts
Right now the run in a way that it simulates how a session might happen between the different parties. It does not address issues or errors that might come up.

To simulate this, start by running the cache.py. Then start the server.py and they will start a handshake, when that is done, give server.py an input in the console
and it will send that to the cache for which will in turn store it for later transmission. You can start server.py several times to store several messages.

When you've stored what you want in the cache, start client.py and watch the handshake play out again before the cache will send to client the previously stored messaged that it got from the server.
