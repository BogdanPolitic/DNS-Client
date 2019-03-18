# DNS-Client
The DNS-Client service resolves the IP - Domain association. On users input, let's say we want to interogate google.com, the web assistant offers an answer. The client returns the IP of the web page requested, as well as the web page answer to the interogation request.

More details about the client implementation are shown in the "README" file.
A complete program functionality documentation is found in the "Task.pdf" file.

Running steps (short example):

Go to project's directory

--> make

--> ./dnsclient [domain_name] [query_type]

where, for example, domain_name=google.com and query_type=A

--> cat dns.log
