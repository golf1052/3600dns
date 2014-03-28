3600dns
=======

A DNS client program by Sanders Lauture & Chris Kuffert

This is a project for the class Systems and Networks taught by the glorious professor Alan Mislove. This code does not complete the extra credit. This code is also pretty terrible and probably could be optimized and cleaned up but it works and it's our child...thing. Enjoy.

Readme for the project
----------------------

We first process the server and port combo by first checking to see if the serverport combo has a colon in it. If it does then there is a port in the combo and we break that off as its own part. We then copy the server into its own character array. If there is not a port number we use the default port number 53. We then construct the header with the approprate information. The struct is specially setup for gcc so that we can just copy the header directly into a character array. We then create the question part by breaking up the name by the period character. We also determine how many characters are between each of the period characters. We then use this information to construct the QNAME. After creating the QNAME we copy that into the a dnsquestion struct. We then copy the header and the question into a buffer so that it is ready to be sent to the server.

After getting a response back from the server we start to process the response. We first read back in the header. This is important so that we can know how many answers to expect. We then check the rcode for errors. If there are no errors we then take out the pointers in the response. This involves looking to see if there is a pointer, following the pointer, getting the data that the pointer is pointing to, then returning that data. After we then process the fixed response (the response with no pointers). We read all the values and then return an answer.

The most challenging part was the one bug we faced. We knew that pointers can lead to other pointers so we made our pointer following function recursive. However we were running into an loop in some cases. We then realized that it was because we were running back into the pointer we came from and just kept looping from there. To fix this we added another variable that kept track of where the pointer came from. If we run into that pointer again we know we are done with that part of the pointer.

We are proud of the pointer deconstructor code. It does a good job of uncompressing a packet back into a form that is easier to manage. However this does come with its downsides. Because we change around the packet the rdlength will not always be correct. This can happen if the answer is a CNAME and the rdata has a pointer in it. The rdlength will only count up to the actual pointer, not where the pointer follows to. To combat this we just recalculate how long the rdlength is by counting how big the CNAME is.

To test code we mainly used Google's DNS (8.8.8.8) after we had fully correct packets and then checked our output againt output from Wireshark. We also used Wireshark for debugging. By following along in our response parsing compared to Wireshark we could see where bugs were happening.
