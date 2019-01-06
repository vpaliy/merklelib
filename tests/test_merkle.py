# -*- coding: future_fstrings -*-
import unittest
import hashlib
import math
import string

try:
  import unittest.mock as mock
except ImportError:
  import mock

from os import urandom
from random import choice

from merklelib import utils
from merklelib.merkle import (
    Hasher,
    MerkleNode,
    MerkleTree,
    AuditProof,
    AuditNode,
    LEFT,
    RIGHT,
    UNKNOWN
)


leaf = b'765f15d171871b00034ee55e48f'


def hashfunc(x):
  return hashlib.sha256(x).digest()

# used for side effects
def mirror(x):
  return x

# Adding __dict__ would allow to mock prototype methods
class MerkleNode(MerkleNode):
  __slots__ = ('__dict__', )


def patchdescriptor(cls, method, new):
  if not hasattr(cls, method):
    raise RuntimeError(f'{method} not found')
  def _patchdescriptor(func):
    def _wrapper(*args, **kwargs):
      try:
        current = getattr(cls, method)
        setattr(cls, method, new)
        result = func(*args, **kwargs)
      finally:
        setattr(cls, method, current)
    return _wrapper
  return _patchdescriptor


def _calculate_root(hashfunc, nodes):
  while len(nodes) > 1:
    if len(nodes) % 2 != 0:
      nodes.append(nodes[-1])
    a = iter(nodes)
    nodes = []
    for l, r in zip(a, a):
      hashval = l
      if hashval != r:
        hashval = hashfunc(l, r)
      nodes.append(hashval)
  return nodes[0]


class MerkleTreeTestCase(unittest.TestCase):
  def test_hasher(self):
    children = leaf * 2

    hasher = Hasher(hashfunc)
    classname = hasher.__class__.__name__

    self.assertEqual(hasher.hash_leaf(leaf), hashfunc(b'\x00' + leaf))
    self.assertEqual(hasher.hash_children(leaf, leaf), hashfunc(b'\x01'+children))
    self.assertNotEqual(hasher.hashfunc, hashfunc)
    self.assertEqual(hasher.hashfunc.__wrapped__, hashfunc)
    self.assertEqual(str(hasher), f'{classname}({hashfunc})')
    self.assertEqual(repr(hasher), f'{classname}({hashfunc})')

  def test_merkle_node(self):
    hashval = hashfunc(leaf)

    left, right = MerkleNode(hashval), MerkleNode(hashval)
    node = MerkleNode(hashval, left=left, right=right)

    self.assertRaises(TypeError, MerkleNode, None)
    self.assertRaises(TypeError, MerkleNode, bytes())
    self.assertEqual(left.parent, right.parent)
    self.assertEqual(left.hash, hashval)
    self.assertEqual(right.hash, hashval)
    self.assertEqual(left.type, LEFT)
    self.assertEqual(right.type, RIGHT)
    self.assertEqual(left.sibiling, right)
    self.assertEqual(right.sibiling, left)
    self.assertEqual(node.type, UNKNOWN)
    self.assertIsNone(node.sibiling)

  @patchdescriptor(MerkleNode, 'type', UNKNOWN)
  def test_merkle_node_combine(self):
    hasher = Hasher(hashfunc)
    lefthash = hashfunc(b'\x01'+leaf)
    righthash = hashfunc(b'\x02'+leaf)

    left, right = MerkleNode(lefthash), MerkleNode(righthash)
    node = MerkleNode.combine(hasher, left, right)

    def _assert_all(finalhash):
      self.assertEqual(node.hash, finalhash)
      self.assertEqual(left.parent, right.parent)
      self.assertEqual(left.hash, lefthash)
      self.assertEqual(right.hash, righthash)
      self.assertEqual(left.sibiling, right)
      self.assertEqual(right.sibiling, left)

    _assert_all(hasher.hash_children(lefthash, righthash))

    # testing concat(right, left)
    left.type = RIGHT; right.type = LEFT
    node = MerkleNode.combine(hasher, left, right)

    _assert_all(hasher.hash_children(righthash, lefthash))

    # another case of concat(right, left)
    left.type = LEFT
    node = MerkleNode.combine(hasher, left, right)

    _assert_all(hasher.hash_children(righthash, lefthash))

  @mock.patch('merklelib.utils.to_hex', autospec=True)
  def test_audit_proof(self, to_hex_mock):
    to_hex_mock.side_effect = mirror

    hashes = [f'{urandom(2048)}{leaf}' for i in range(65)]
    nodes = [AuditNode(hash, choice([LEFT, RIGHT])) for hash in hashes]

    proof = AuditProof(nodes)
    items = ', '.join(hashes)
    string = f'{{{items}}}'

    self.assertEqual(proof.hex_nodes, hashes)
    self.assertEqual(repr(proof), string)
    self.assertEqual(str(proof), string)

  @mock.patch('merklelib.utils.to_hex', autospec=True)
  def test_merkle_tree_init(self, to_hex_mock):
    to_hex_mock.side_effect = mirror

    hasher = Hasher(hashfunc)
    leaves = [f'{urandom(2048)}{leaf}' for i in range(65)]
    hashes = [hasher.hash_leaf(leaf) for leaf in leaves]

    # testing _init_hashfunc
    self.assertRaises(TypeError, MerkleTree, leaves, leaves)
    self.assertRaises(ValueError, MerkleTree, None)

    tree = MerkleTree('a', mirror)
    self.assertEqual(tree.hasher.hashfunc.__wrapped__, mirror)

    tree = MerkleTree('a', None)
    self.assertIsNotNone(tree.hasher)

    # basic check
    tree = MerkleTree(leaves, hasher)
    self.assertEqual(tree.hexleaves, hashes)
    self.assertEqual(tree.merkle_root,
      _calculate_root(hasher.hash_children, hashes))

    # converting non iterable leaves to tuples
    tree = MerkleTree('a', hasher)
    self.assertEqual(tree.hexleaves, [hasher.hash_leaf('a')])
    self.assertEqual(tree.merkle_root, hasher.hash_leaf('a'))

  @mock.patch('merklelib.utils.to_hex', autospec=True)
  def test_merkle_tree_get_proof(self, to_hex_mock):
    to_hex_mock.side_effect = mirror

    chars = list(string.ascii_letters)
    tree = MerkleTree(chars, hashfunc)

    self.assertEqual(tree.get_proof('invalid'), AuditProof([]))
    for char in chars:
      proof = tree.get_proof(char)
      self.assertEqual(len(proof), math.ceil(math.log(len(chars), 2)))
