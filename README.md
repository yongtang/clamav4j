ClamAV4j
========

A Java library for ClamAV
-----------------------


This Java library is intended to be served as a bridge between a Java application or web service and the ClamAV antivirus engine. With ClamAV4j, virus detection could be performed for any content that comes from outside.

The library uses TCP socket (INET) to communicate with ClamAV daemon (clamd) through ClamAV's INSTREAM command. To use ClamAV4j library, either use the blocking connection Class:

```
class ClamAV
```

or use the asynchronous Class:

```
class ClamAVAsync
```

Performance
-----------
For ClamAVAsync class, it may offer better performance with multi-core processors. On the other hand, blocking ClamAV class allows the usage of FileChannel, which may bypass buffer copy under certain situations. It is best to test with the real scenario to make a selection between the two classes.

Contact
-------
If you have trouble with the library or have questions, check out the GitHub repository at http://github.com/yotang/clamav4j and I’ll help you sort it out.
