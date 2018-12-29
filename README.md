# merkle-trees


## Diagrams

<img src="https://github.com/vpaliy/merkle-trees/blob/master/ext/general.jpg"  />


## Usage

```python
 from merkle import MerkleTree, beautify
 
 
 transactions = get_transactions(user) # random data
 tree = MerkleTree(transactions)
 
 beautify(tree) # print the tree in the terminal
```

Output:

```
571c427627aa472d9ddf4bf537900d9aad176f40a6e1c87b894516319cb36488
├── b231dd15cb77c16d1cfe1f8d4c85b9a659b92e5d0ca77433e7c1817943571e29
│   ├── bd0d284681adfa41a5c670b7fa0cec4827311471d85a59e79489dd8818f25864
│   │   ├── 6016c25c8b2937bbc3b4d138fef9059fc4bfacf0238030b4a57c89c7a54d67a4
│   │   └── f08675799e4471bcc0b987d0cb149db77b93dea26e83c845dcbb46cbc1cc993a
│   └── 76280ab887dad46795953248e57c19ece04649eaa42beded59907e25291c075f
│       ├── 218197693424e0154cefc0af31aed96c084b987e08136e91d5528ddbb5461e24
│       └── 580eedc669f3b989d0a0be1988b583af29a45a9edf5ca8375c36818d2c44ee4a
└── 63387f98b573eeb5f92403dc3d53e37b2a07df512a7600c41c618b522cc4158f
    ├── eff767a2012fa2e3bceec3ba42c319a801c9e7120184c4a12942f6eb0cbf11c5
    │   ├── 4876f89796260f971c5fff6978e37708acc9a36ae1e99ff1ec4e750a844d86a3
    │   └── 582967534d0f909d196b97f9e6921342777aea87b46fa52df165389db1fb8ccf
    └── fef7eafb5af4129b89d411b258e77dad493f40cc5a07038a358123de4356e3db
        ├── 26325a546fbbb0238cb2fb3e9266b81084f74de0c37dc9cf67fd1f49b3b1c6c8
        └── 26325a546fbbb0238cb2fb3e9266b81084f74de0c37dc9cf67fd1f49b3b1c6c8
```

You can also export the output above as an image. This is how you'd do it:


```python
 from merkle import MerkleTree, export
 
 
 transactions = get_transactions(user) # random data
 tree = MerkleTree(transactions)
 
 export(tree, filename='transactions', ext='jpg') 
```

Default extension is always `.png`. You can also specify an absolute path.

However, in order to be able to use the `export` function, you may need to install `graphviz` on your machine.
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
