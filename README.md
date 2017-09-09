# ext2ck

## Building

`ext2ck` uses GNU Make along with GCC to build:

```
$ git clone https://github.com/ianbrault/ext2ck && cd ext2ck
$ make
$ ./ext2ck ...
```

## Usage

`ext2ck` requires that you supply the filename of the EXT2 file system image.

The program will scan the image for the following:

* invalid (out of range) or reserved blocks allocated to an i-node
* unused blocks that are *not* marked as free in the block bitmap
* allocated blocks that *are* marked as free in the block bitmap
* blocks referenced in multiple files
* allocated i-nodes that *are* marked as free in the i-node bitmap
* unallocated i-nodes that are *not* marked as free in the i-node bitmap
* allocated i-nodes whose reference count does not match the number of discovered links
* directory entries that refer to invalid/unallocated i-nodes
* directories with invalid `.` and/or `..` entries
