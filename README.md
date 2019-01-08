[![Build Status](https://travis-ci.org/vpaliy/merklelib.svg?branch=master)](https://travis-ci.org/vpaliy/merklelib)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Merkle Trees

Merkle trees are hash-based data structures used to validate large amounts of data in an efficient manner. This data structure is used to solve the previously time-consuming and computationally expensive problem of keeping data consistent across multiple computers. Prominent uses of a Merkle tree - and its variations- are in peer-to-peer networks such as Bitcoin, Ethereum, Git, and Tor.


### Merkle Tree Diagram

This diagram illustrates a fully balanced Merkle tree. As you can guess from the illustration, the Merkle hash root maintains the integrity of the data. If any of the nodes are changed, or the order of the data items is changed, the Merkle hash root will be completely different.  

<img src="https://github.com/vpaliy/merkle-trees/blob/master/ext/merkle.jpg"  />


This is what an "artificially" balanced tree looks like (a tree whose number of leaves is not a power of two):

<img src="https://github.com/vpaliy/merkle-trees/blob/master/ext/empty.jpg"  />

We had to add an empty light-weight node in order to keep it balanced.
Therefore, when we append a new leaf, we can just replace that empty node and recalculate the hash root.


### Merkle Audit Proof

Audit proof lets you verify that a specific data record is included in the database. Usually, the server maintaining the database provides the client with a proof that the record exists in that database. If a Merkle audit proof fails to produce a root hash that matches the Merkle root hash (which is obtained from a trusted authority), it means that the data record is not in the database.

The diagram below illustrates how you should construct an audit proof:

<img src="https://github.com/vpaliy/merkle-trees/blob/master/ext/proof.jpg"  />

In this example, we need to provide a proof that the record `D` exists in the database.
Since we already know the hash value of `D` (we can easily compute it), we will need `H-3` in order to compute `D-2`. Now, when we are able to compute `D-2`, we will need to get `D-1` in order to obtain the hash value of `T-1`, and so on...
You've got the gist, right? We only need to grab the sibling node and climb up the tree until we've reached the root. [This](https://github.com/vpaliy/merklelib/blob/master/merklelib/merkle.py#L468) implements everything described above.


### Merkle Consistency Proof

A Merkle consistency proof lets you verify that any two versions of a database are consistent: that is, the later version includes everything in the earlier version, in the same order, and all new entries come after the entries in the older version.



## Usage

Install it:

`pip install merklelib`

or clone it:

```
$ git clone git clone https://github.com/vpaliy/merklelib.git
```

This snippet demonstrates how to build a Merkle tree and verify leaf inclusion:

```python
import string
import hashlib

from merklelib import MerkleTree

# a sample hash function
# you can also omit it and the default hash function will be used
def hashfunc(value):
  return hashlib.sha256(value).hexdigest()


# a list of all ASCII letters
data = list(string.ascii_letters)

# build a Merkle tree for that list
tree = MerkleTree(data, hashfunc)

# generate an audit proof the letter A
proof = tree.get_proof(hashfunc('A'))

# now verify that A is in the tree
# you can also pass in the hash value of 'A'
# it will hash automatically if the user forgot to hash it
if tree.verify_leaf_inclusion('A', proof):
  print('A is in the tree')
else:
  exit('A is not in the tree')
```

Or you may want to perform a consitency check (using `<`, `<=`, `>`, `>=` operators):

(some code will be omitted)
```python
tree = MerkleTree(get_data())
...
...
...
new_tree = MerkleTree(get_new_data())

# check if the new tree contains the same items
# and in the same order as the old version
if tree <= new_tree:
  print('Versions are consistent')
else:
  exit('Versions are different')
```

Alternatively, you can use the `verify_tree_consitency` function for this:
```python

from  merkelib import MerkleTree, verify_tree_consistency
...
...
...
# information that we need to provide
old_hash_root = old_tree.merkle_hash
old_tree_size = len(old_tree)

# check if the new tree contains the same items
# and in the same order as the old version
if verify_tree_consistency(new_tree, old_hash_root, old_tree_size):
  print('Versions are consistent')
else:
  exit('Versions are different')
```


You can build a Merkle tree and nicely display it in the terminal:

```python
 from merklelib import MerkleTree, beautify


 transactions = get_transactions(user) # random data
 tree = MerkleTree(transactions)

 beautify(tree) # print the tree in the terminal
```

Output:

```
e11a20bae8379fdc0ed560561ba33f30c877e0e95051aed5acebcb9806f6521f
├── 862532e6a3c9aafc2016810598ed0cc3025af5640db73224f586b6f1138385f4
│   ├── fa13bb36c022a6943f37c638126a2c88fc8d008eb5a9fe8fcde17026807feae4
│   │   ├── 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9
│   │   └── 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
│   └── 70311d9d203b2d7e4ff70d7fce219f82a4fcf73a110dc80187dfefb7c6e4bb87
│       ├── d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35
│       └── 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
└── f4685cb09ef9f1c86b2d8f544d89f1c1d3592a3654beb8feecad11e9545e0e72
    ├── 67d62ee831ff99506ce1cd9435351408c3a845fca2dc0f34d085cdb51a37ec40
    │   ├── 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
    │   └── ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d
    └── ac6621607d32037664f03f92a4aae94d4c97f6bbcf438ff20509311681e6b259
        ├── e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683
        └── 7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451
```

You can also export the output above as an image or a JSON file. This is how you'd do it:


```python
 from merklelib import MerkleTree, export


 transactions = get_transactions(user) # random data
 tree = MerkleTree(transactions)

 export(tree, filename='transactions', ext='jpg')
```

Default extension is always `.json.` You can also specify an absolute path.

However, in order to be able to use the `export` function with images, you may need to install `graphviz` on your machine.
Here is how you can do that for Mac and Ubuntu:

### Mac

`brew install graphviz`


### Ubuntu

`sudo apt-get install graphviz`



## Benchmark

I have included some basic benchmark code to measure performance. If you want to try it out, simply download the repository with:

```
$ git clone git clone https://github.com/vpaliy/merklelib.git
$ cd merklelib
```

And run it with `python3` or `python2` (additional arguments are optional):

```
$ python3 benchmark --size=2048 -a=8

  Building: 0.016072 seconds.
  Appending: 0.000868 seconds.
  Tree size: 637401
  Number of leaves: 2056

  Audit proof verification times:
   Average time: 0.00014690807392996172 seconds.
   Total time: 0.304746 seconds.
   Longest time: 0.000325 seconds.
   Shortest time: 5.9e-05 seconds.

  Consitency proof verification times (2056 trees):
   Average time: 0.008714925583657588 seconds.
   Total time: 17.925458 seconds.
   Longest time: 0.035517 seconds.
   Shortest time: 9e-05 seconds.

```

The above test provides the following results:
 - how long it takes to build a Merkle tree.
 - how long it takes append additional leaves.
 - how long it takes to verify every single leaf that is included in the tree.
 - how long it takes to prove that every possible sub-tree of the generated Merkle tree is consistent with the original one


You can also build your own benchmark. Here's a simple one that measure how long it takes to build a Merkle tree with 65536 leaves:

```
>>> import os
>>> import timeit
>>> from merklelib import MerkleTree
>>> leaves = [os.urandom(2048) for i in range(2**16)]
>>> def timeav(code, n=20):
>>>  return timeit.timeit(
...    code, setup="from __main__ import MerkleTree, leaves", number=n)/n
...
# time taken to build the tree
>>> print timeav("MerkleTree(leaves)")
0.70325

```

# Resources

* [Understanding Merkle Trees - Why use them, who uses them, and how to use them](https://www.codeproject.com/Articles/1176140/%2FArticles%2F1176140%2FUnderstanding-Merkle-Trees-Why-use-them-who-uses-t)

* [Certificate Transparency](https://tools.ietf.org/html/rfc6962#section-2.1.2)

* [Merkle Tree Brilliant](https://brilliant.org/wiki/merkle-tree/)

# License
```
MIT License

Copyright (c) 2019 Vasyl Paliy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
