# Authentication tutorial
----

This tutorial makes use of Go features to implement HTTP Basic Authentication mechanism.

## Basic Authentication

HTTP Basic Authentication is an authentication mechanism that makes use of the HTTP header _Authorization_. This header
contains the user's username and password encoded with _base-64_ in the following way: 

````
Authorization: Basic username:password
````

A concrete example for the credentials _alice:pa55word_ would be:

````
Authorization: Basic YWxpY2U6cGE1NXdvcmQ=
````

By using an encoding mechanism the server can decode the header's content and validate the credentials.