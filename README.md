coldfusion-rsa
==============

CFC-Component for asymmetric key cryptograph using java security

As I could not find asymmetric cryptography in Coldfusion I built this component.

The component has the following features:

1. Create a key pair (private and public key)
1. Encrypt a text-string with one key
1. Decrypt an encrypted string with the other key
1. Create a key object from a base64 key-string or binary key 

Support
-------

Has been tested with Adobe CF8, CF9, CF10 and Railo 4

For CFMX7 you might want to have a look at the [Adobe KnowledgeBase][2]

Resources
---------

Documentation for this component can be found on the [GitHub Wiki][1].

[1]: https://github.com/ggfx/coldfusion-rsa/wiki
[2]: http://helpx.adobe.com/coldfusion/kb/strong-encryption-coldfusion-mx-7.html