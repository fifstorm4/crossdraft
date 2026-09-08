"""
Building a classpath for `java -cp`.

Its own module because everything here shells out to Java and nothing else
should have to import a cipher translator to do it -- digbuild in particular
cannot, since dig2claasp reads what digbuild writes.
"""

import os

__all__ = ["classpath"]


def classpath(*jars):
    """
    Join jar paths the way the local JVM expects.

    The separator is a colon on Unix and a semicolon on Windows.  Hard-coding
    the colon makes Windows read the whole string as one path, and the failure
    is `ClassNotFoundException` naming a class that is plainly present in the
    jar -- which reads as a broken build rather than a quoting mistake, and
    cost a full CI round trip to recognise.
    """
    return os.pathsep.join(str(j) for j in jars if j)
