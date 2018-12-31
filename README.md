# merkle-trees

### Merkle Tree Diagram

<img src="https://github.com/vpaliy/merkle-trees/blob/master/ext/merkle.jpg"  />


### Merkle Audit Proof Diagram

<img src="https://github.com/vpaliy/merkle-trees/blob/master/ext/proof.jpg"  />


## Usage

```python
 from merkle import MerkleTree, beautify


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
 from merkle import MerkleTree, export


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


# License
```
MIT License

Copyright (c) 2018 Vasyl Paliy

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
