# -*- coding: future_fstrings -*-
import unittest

try:
  import unittest.mock as mock
except ImportError:
  import mock

from merklelib.merkle import Hasher


class MerkleTreeTestCase(unittest.TestCase):
  def test_hasher(self):
    leaf = b'abcdef'
    children = leaf * 2
    hashfunc = lambda x: x

    hasher = Hasher(hashfunc)

    self.assertEqual(hasher.hash_leaf(leaf), b'\x00'+leaf)
    self.assertEqual(hasher.hash_children(leaf, leaf), b'\x01'+children)
    self.assertEqual(hasher.hashfunc, hashfunc)
