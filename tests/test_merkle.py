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
    UNKNOWN,
    verify_leaf_inclusion,
    verify_tree_consistency
)

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


# commonly used objects across tests
hasher = Hasher(hashfunc)
leaf = b'765f15d171871b00034ee55e48f'

to_hex = mock.patch('merklelib.utils.to_hex', side_effect=mirror)
to_hex.start()


class MerkleTestCase(unittest.TestCase):
  def test_hasher(self):
    children = leaf * 2
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

  def test_audit_proof(self):
    hashes = list(string.ascii_letters)
    nodes = [AuditNode(hash, choice([LEFT, RIGHT])) for hash in hashes]

    proof = AuditProof(nodes)
    items = ', '.join(hashes)
    items_str = f'{{{items}}}'

    self.assertEqual(proof.hex_nodes, hashes)
    self.assertEqual(repr(proof), items_str)
    self.assertEqual(str(proof), items_str)

  def test_merkle_tree_init(self):
    leaves = list(string.ascii_letters)
    hashes = [hasher.hash_leaf(leaf) for leaf in leaves]

    # testing _init_hashfunc
    self.assertRaises(TypeError, MerkleTree, leaves, leaves)

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

    # test case for empty root
    tree = MerkleTree()
    self.assertEqual(tree.hexleaves, [])
    self.assertEqual(tree.merkle_root, None)

  def test_merkle_tree_get_proof(self):
    chars = list(string.ascii_letters[:32])
    tree = MerkleTree(chars, hasher)

    self.assertEqual(tree.get_proof('invalid'), AuditProof([]))

    # proof should contain log2 (n) of nodes
    for char in chars:
      expected = math.ceil(math.log(len(chars), 2))
      # check for simple chars
      proof = tree.get_proof(char)
      self.assertEqual(len(proof), expected)
      # check for hashed leaves
      proof = tree.get_proof(hasher.hash_leaf(char))
      self.assertEqual(len(proof), expected)

  def test_merkle_tree_update(self):
    chars = string.ascii_letters
    hash_mapping = {char: hasher.hash_leaf(char) for char in chars}

    tree = MerkleTree(chars, hasher)
    initial_merkle_root = tree.merkle_root
    # calculate the merkle root manually from hashes
    current_root = _calculate_root(
      hasher.hash_children,
      hash_mapping.values()
    )

    self.assertEqual(initial_merkle_root, current_root)
    self.assertRaises(KeyError, tree.update, 'invalid', 'a')

    for a, b in zip(chars, chars[::-1]):
      prev_merkle_root = current_root
      hash_mapping[a] = hasher.hash_leaf(b)

      # swap values
      tree.update(a, b)

      # calculate the merkle root manually from hashes
      current_root = _calculate_root(
        hasher.hash_children,
        hash_mapping.values()
      )

      self.assertNotEqual(tree.merkle_root, initial_merkle_root)
      self.assertNotEqual(tree.merkle_root, prev_merkle_root)
      self.assertEqual(tree.merkle_root, current_root)

      # same thing for hash values for leaves
      tree.update(hasher.hash_leaf(a), hasher.hash_leaf(b))

      self.assertNotEqual(tree.merkle_root, initial_merkle_root)
      self.assertNotEqual(tree.merkle_root, prev_merkle_root)
      self.assertEqual(tree.merkle_root, current_root)

  def test_merkle_tree_append(self):
    ascii = string.ascii_letters
    hashes = [hasher.hash_leaf(char) for char in ascii]

    tree = MerkleTree(hashobj=hasher)

    # hash as one string
    tree.append(ascii)
    expected_hash = hasher.hash_leaf(ascii)

    self.assertEqual(len(tree), 1)
    self.assertEqual(tree.merkle_root, expected_hash)

    # append every ascii character
    tree.clear(); tree.extend(ascii)
    expected_hash = _calculate_root(hasher.hash_children, hashes)

    self.assertEqual(len(tree), len(ascii))
    self.assertEqual(tree.merkle_root, expected_hash)

    # test all cases
    for limit in range(1, len(ascii)):
      tree.clear(); tree.extend(ascii[:limit])
      expected_hash = _calculate_root(hasher.hash_children, hashes[:limit])

      self.assertEqual(len(tree), limit)
      self.assertEqual(tree.merkle_root, expected_hash)

  def test_merkle_tree_equals(self):
    a = MerkleTree(string.ascii_letters)
    b = MerkleTree(string.ascii_letters)

    self.assertEqual(a, b)
    self.assertTrue(a.__eq__(b))
    self.assertTrue(b.__eq__(a))

    a.append(1); b.append(2);

    self.assertIsNot(a, b)
    self.assertFalse(a.__eq__(b))
    self.assertFalse(b.__eq__(a))

  def test_verify_leaf_inclusion(self):
    self.assertRaises(TypeError, verify_leaf_inclusion)
    self.assertRaises(TypeError, verify_leaf_inclusion, None, None, hashfunc)

    tree = MerkleTree(string.ascii_letters, hasher)
    merkle_root = tree.merkle_root

    for leaf in string.ascii_letters:
      proof = tree.get_proof(leaf)
      hashval = hasher.hash_leaf(leaf)

      self.assertEqual(tree.get_proof(hashval), proof)
      self.assertTrue(verify_leaf_inclusion(leaf, proof, hashfunc, merkle_root))

  def test_verify_tree_consistency(self):
    self.assertRaises(TypeError, verify_tree_consistency)
    self.assertFalse(verify_tree_consistency(MerkleTree(), None, 10))

    tree = MerkleTree(string.ascii_letters)
    merkle_root = tree.merkle_root

    self.assertTrue(verify_tree_consistency(tree, merkle_root, len(tree)))

    for size in range(1, len(tree)):
      old_tree = MerkleTree(string.ascii_letters[:size])
      merkle_root = old_tree.merkle_root
      self.assertTrue(verify_tree_consistency(tree, merkle_root, size))
