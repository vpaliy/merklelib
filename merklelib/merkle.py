# -*- coding: future_fstrings -*-
# -*- coding: utf-8 -*-

"""Merkle trees.

Sample code snippet:

>>> from merklelib import MerkleTree, beautify
>>> import hashlib
>>> hashfunc = lambda x: hashlib.sha256(str(x).encode()).hexdigest()
>>> tree = MerkleTree(get_data(), hashfunc)
>>> beautify(tree)
c9f33d24dd8e472976c0198b0f836b3874b5c6467eb23cc1adf7b687ac586498
├── d28b1b2d721c2ccc607af28cfbb419013bc942927d04392ee0c1dc2a9066a81d
│   ├── e8fe3173b1b0986b3d790924ff035f7180becf69bc1ffd169bf00f3282e0c24b
│   │   ├── 8da651a777f744d24c3dfe78e4aba4db4b38c0503b751976a1deca5791d4f104
│   │   └── 2793603d2dbc9ecb01075e8ee79c9705840bfde2d7e04ddfc952aea2ae46e79c
│   └── 677faacca2f4bf2c6ffcd46a7a1f1dfcf693399782072f9abf3c2c6a696e3a25
│       ├── 6ee8afcc0c19ab6c4193a332f862a85931093e425e417a598e9586c118fbcd47
│       └── 01849571e994a62e59b9ec206cd0bd979349d6462b6cc2ecb8c79b2da5132f51
└── 33f61b85350855f9b3f6b72ff82e69a13e5a9558257ac070a6ea0b4221993afa
    ├── 3b7ff0501fc23acda03364ff531814d0052958314774af33dda4bf7a0ab31de9
    │   ├── 7fc3c4c5ce8ddbe92d0cc088e16453a7de577ea2550e5c488b567e5405589cb9
    │   └── 125f0aa386a98c76a2da004a97c65f22a09604df1af359ef8998da3220214b0d
    └── a72b9a1cc7b60477746a12c0d94281878bf5475d0ae8b474dc614165f99dbe82
        ├── a18ae51c18a80e1d68422384fb497382059c64197267646e9eae863de83ec3ec
        └── f72db255ff769c583833da5417f460ea4af0c588e0c5291626e51726462ffb94

Copyright: (c) 2018 by Vasyl Paliy.
License: MIT, see LICENSE for more details.
"""

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import with_statement

import hashlib
import collections
import abc
import six
import functools
import io
import math
import time

from merklelib import utils

# used to indicate whether a leaf (or node) is the left or right child
# or unknown yet
LEFT, RIGHT, UNKNOWN = tuple(range(3))


# used as a "duplicate" node in the Merkle tree
# utilizing this light-weight object helps to keep the tree balanced
# (in other words, the number of nodes should be power of 2)
_empty = object()


# hash function which is supplied when the user
# does not provide his/her hashing mechanism
def _default_hash(value):
  value = utils.to_string(value)
  return hashlib.sha256(value).hexdigest()


def _hash_from_hex(func):
  """A decorator that converts hashes from hexadecimal strings to bytes.

  :param func: a hash function that presumably returns a hexadecimal string.
  :return _wrapper: a function that converts hexadecimal strings to bytes.
  """
  # keep it dry
  if hasattr(func, '_hex_decorator'):
    return func._hex_decorator
  @functools.wraps(func)
  def _wrapper(*args, **kwargs):
    hash_value = func(*args, **kwargs)
    return utils.from_hex(hash_value)
  func._hex_decorator = _wrapper
  _wrapper.__wrapped__ = func
  return _wrapper


class Hasher(object):
  """Merkle hasher that appends additional bytes to leaves and nodes before hashing.

  This prevents the second preimage attack scenario in which an attacker creates a
  tree other than the original but with the same Merkle hash root.

  Attributes:
    hashfunc: a function that consumes an object and returns its hash value.
      Ideally, the returned hash value is a hexadecimal string.
  """

  def __init__(self, hashfunc=_default_hash):
    if not callable(hashfunc):
      raise TypeError(f'Expected callable, got {type(hashfunc)}')
    self.hashfunc = hashfunc

  def hash_leaf(self, data):
    data = b'\x00' + utils.to_string(data)
    return self._hashfunc(data)

  def hash_children(self, left, right):
    data = b'\x01' + left + right
    return self._hashfunc(data)

  @property
  def hashfunc(self):
    return self._hashfunc

  @hashfunc.setter
  def hashfunc(self, hashfunc):
    self._hashfunc = _hash_from_hex(hashfunc)

  def __repr__(self):
    classname = self.__class__.__name__
    hashfunc = self._hashfunc.__wrapped__
    return f'{classname}({hashfunc})'

  def __str__(self):
    return repr(self)


# Helper functions
def _pairwise(iterable):
  a = iter(iterable)
  return zip(a, a)


def _get_hash(obj):
  if isinstance(obj, _BaseNode):
    return utils.to_string(obj.hash)
  return utils.to_string(obj)


def _concat(hasher, *nodes):
  """Concatenate the hashes of two nodes using the provided hasher object.

  :param hasher: Hasher object for hashing nodes.
  :param nodes: nodes that should be concatenated.
    Usually, descendants of _BaseNode, hexadecimal strings, _empty nodes or mixed.
  :return: the hash value produced by concatenation of provided nodes.
  """
  def __concat(x, y):
    # we can't concatenate _empty nodes
    # return the hash value of the not _empty object
    if (x is _empty) or (y is _empty):
      return x.hash if y is _empty else y.hash
    children = (_get_hash(x), _get_hash(y))
    # x.type == RIGHT or y.type == LEFT indicates y + x
    if isinstance(x, _BaseNode) and x.type == RIGHT:
      return hasher.hash_children(*children[::-1])
    elif isinstance(y, _BaseNode) and y.type == LEFT:
      return hasher.hash_children(*children[::-1])
    return hasher.hash_children(*children)
  return functools.reduce(__concat, nodes)


def _climb_to(node, level):
  """Traverses the Merkle Tree to a certain level.

  :param node: marks the starting point from which we begin climbing up the tree.
  :param level: an integer that indicates how many levels we need to climb.
  :return: ancestor of the provided node object at the specified level of the tree.
     None if the starting node doesn't have ancestors at the requested level.
  """
  while (level > 0) and node:
    level -= 1
    node = node.parent
  return node


def verify_tree_consistency(new_tree, old_root, old_size):
  """Verifies that the new tree contains the same nodes
   and in the same order as a given subtree.

  :param new_tree: Merkle tree whose certain nodes will be
    concatenated and hashed to produce the Merkle hash root of a subtree;
    thus proving consistency of both trees.
  :param old_root: the Merkle hash root of the old tree (or a subtree).
  :param old_size: number of leaves in the old tree.
  :return: True if both the old and new trees are consistent.
  """
  if not isinstance(new_tree, MerkleTree):
    raise TypeError(f'Expected MerkleTree, got {type(new_tree)}')

  new_size = len(new_tree)
  # the number of leaves in the old tree
  # cannot be greater than in the new tree
  if new_size < old_size:
    return False

  # assuming both hashes are hexadecimal strings
  old_root = utils.from_hex(old_root)
  new_root = utils.from_hex(new_tree.merkle_root)

  # if the number of leaves is identical
  # then roots also must be identical
  if new_size == old_size:
    return old_root == new_root

  leaves = new_tree.leaves
  index, paths = 0, []

  while old_size > 0:
    # level is the largest power of two smaller than old_size
    # log2(level) will indicate where we should be climbing
    level = 2**(old_size.bit_length() - 1)
    node = _climb_to(leaves[index], math.log(level, 2))
    if node is None:
      return False
    paths.append(node)
    index += level
    old_size -= level

  # if old_size is power of two (len(paths) == 1)
  # then we have our searched Merkle hash root
  # otherwise we will need to concatenate all nodes
  if len(paths) > 1:
    paths = paths[::-1]
    hasher = new_tree.hasher
    concat = lambda a,b: _concat(hasher, a, b)
    new_root = functools.reduce(concat, paths)
  else:
    new_root = paths[0].hash
  return new_root == old_root


def verify_leaf_inclusion(target, proof, hashobj, root_hash):
  """Verifies that a tree includes a leaf.

  :param target: a leaf which is represented by either a real object
    (int, str, etc.) or the hash value of that object.
  :param proof: a data structure that contains
    AuditNode objects which serve to recreate the original Merkle hash root.
  :param hashobj: a hash function or Hasher. If a hash function is provided,
    it will be used to convert a Hasher instance.
  :param root_hash: Merkle hash root provided by a trusted authority.
  :return: True if the leaf is included in the tree.
  """
  if not isinstance(hashobj, Hasher):
    if not callable(hashobj):
      raise TypeError(f'Expected callable, got {type(hashobj)}')
    hashobj = Hasher(hashobj)

  hasher = hashobj
  paths = None

  # any collection containing AuditNode objects.
  if isinstance(proof, collections.Iterable):
    if isinstance(proof[0], AuditNode):
      paths = proof
  elif isinstance(proof, AuditProof):
    paths = proof._nodes

  if paths is None:
    raise TypeError(
      'Proof must be either <AuditProof>, '
      'a collection of <AuditNode> objects.'
      )
  # keep it dry
  concat = lambda x,y: _concat(hasher, x, y)
  def _calculate_root(target):
    _proof = [target] + paths
    return functools.reduce(concat, _proof)

  new_root = _calculate_root(target)
  root_hash = utils.from_hex(root_hash)
  # try again if the user forgot to hash the target
  if new_root != root_hash:
    try:
      new_root = _calculate_root(hasher.hash_leaf(target))
    except:
      pass
  return new_root == root_hash


@six.add_metaclass(abc.ABCMeta)
class _BaseNode(object):
  """Data structure that contains attributes common to all nodes.

  Attributes:
    hash: the hash value of an object.
    type: an integer that indicates whether
      the node is the left or right child of its parent.
  """

  __slots__ = ('hash', 'type',)

  def __init__(self, hash, type):
    self.hash = hash
    self.type = type

  def __eq__(self, other):
    return all([
      isinstance(other, _BaseNode),
      self.hash == other.hash,
      self.type == other.type
    ])

  def __repr__(self):
    name = type(self).__name__
    return f'<{name} {self.hash}>'

  def __str__(self):
    return repr(self)


class MerkleNode(_BaseNode):
  """Represents the leaves and nodes in a Merkle tree."""

  __slots__ = ('left', 'right', 'parent',)

  def __init__(self, hash, left=None, right=None, parent=None):
    # accept only non empty hashes
    if not hash:
      raise TypeError('Invalid hash')
    self.hash = hash
    self.left = left
    self.right = right

    # if children nodes are not _empty
    # automatically assign itself as their parent
    if left and (left is not _empty):
      left.parent = self
    if right and (right is not _empty):
      right.parent = self
    self.parent = parent

  @property
  def sibiling(self):
    parent = self.parent
    if parent is None:
      return None
    if parent.left is self:
      return parent.right
    elif parent.right is self:
      return parent.left
    return None

  @property
  def type(self):
    parent = self.parent
    if parent is None:
      return UNKNOWN
    return LEFT if (parent.left is self) else RIGHT

  @classmethod
  def combine(cls, hasher, left, right):
    """Provided two nodes, create a parent node for them."""
    return cls(_concat(hasher, left, right), left, right)


class AuditNode(_BaseNode):
  """Serves as the fundamental entity in
     the audit proof validation process."""

  def __init__(self, hash, type):
    self.hash = hash
    self.type = type


class AuditProof(object):
  """Container of all AuditNode objects."""

  def __init__(self, nodes):
    self._nodes = nodes

  @property
  def hex_nodes(self):
    # Convert all nodes to hexadecimal strings
    if not hasattr(self, '_hex_nodes'):
      self._hex_nodes = [
        utils.to_hex(n.hash) for n in self._nodes
      ]
    return self._hex_nodes

  def __len__(self):
    return len(self._nodes)

  def __eq__(self, other):
    return all([
      isinstance(other, AuditProof),
      len(self) == len(other),
      set(self.hex_nodes) == set(other.hex_nodes)
    ])

  def __repr__(self):
    items = ', '.join(self.hex_nodes)
    return f'{{{items}}}'

  def __str(self):
    return repr(self)


@functools.total_ordering
class MerkleTree(object):
  """Representation of a Merkle tree.

  Usage::
    >>> import merklelib
    >>> tree = merklelib.MerkleTree(get_transactions(), hashfunc)
      <MerkleTree[fae70231a0f537eb32be3570c3d57fe3db18098dc9c0c0ff30f5bef937c617c5]>
  """

  def __init__(self, data=None, hashobj=None):
    """
    :param data: a collection of items (or an item) that is
        used to build the tree.
    :param hashobj: a hashing mechanism to be used while building the tree.
        It is either a hash function or a Hasher instance.
    """
    data = data or []
    self._init_hashfunc(hashobj)
    self._build_tree(data)

  def _init_hashfunc(self, hashobj):
    if hashobj is None:
      hashobj = Hasher(_default_hash)
    elif callable(hashobj):
      hashobj = Hasher(hashfunc=hashobj)
    if not isinstance(hashobj, Hasher):
      raise TypeError('hashobj must be a function or Hasher')
    self._hasher = hashobj

  def _build_tree(self, data):
    # convert to a tuple if not iterable already
    if not isinstance(data, collections.Iterable):
      data = (data, )
    self._root = None
    mapping = collections.OrderedDict()
    hasher = self._hasher
    nodes = [MerkleNode(hasher.hash_leaf(item)) for item in data]
    leaves = list(nodes)
    # build the tree and compute the merkle hash root
    while len(nodes) > 1:
      if (len(nodes) % 2) != 0:
        nodes.append(_empty)
      nodes = [MerkleNode.combine(hasher, l, r) for l, r in _pairwise(nodes)]
    if len(leaves) > 0:
      # save all leaves
      for leaf in leaves:
        mapping[leaf.hash] = leaf
      self._set_root(nodes[0])
    self._mapping = mapping

  def get_proof(self, leaf):
    """Provides an audit proof for a leaf.

    :param leaf: a leaf which is represented by either a real object
      (int, str, etc.) or the hash value of that object.
    :return audit proof: a collection of all hashes
      such that if traversed and concatenated,
      will produce the original merkle hash root
    """
    mapping, hasher = self._mapping, self._hasher
    # assuming that leaf in hexadecimal representation
    target = mapping.get(leaf)
    if target is None:
      target = mapping.get(hasher.hash_leaf(leaf))
    # no leaf in mapping, return an empty AuditProof object
    if not isinstance(target, MerkleNode):
      return AuditProof([])
    root, paths = self._root, []
    # saving every sibiling node (if not _empty)
    # until the root node is reached
    while target is not root:
      sibiling = target.sibiling
      if sibiling is not _empty:
        node = AuditNode(sibiling.hash, sibiling.type)
        paths.append(node)
      target = target.parent
    return AuditProof(paths)

  def _rehash(self, node):
    root, hasher = self._root, self._hasher
    # rehash nodes all the way to the root
    while node is not root:
      parent = node.parent
      sibiling = node.sibiling
      parent.hash = _concat(hasher, node, sibiling)
      node = parent

  def update(self, old, new):
    """Updates a leaf.

    :param old: a leaf that is already in the tree.
      It can by either a real object (int, str, etc.)
      or the hash value of that object.
    :param old: a leaf that will replace the old one.
    """
    # accepting leaves of the same type only
    if type(old) != type(new):
      raise TypeError(
        'Old and the new value are of different types.'
        'You should hash them to avoid the error.'
      )
    mapping, hasher = self._mapping, self._hasher
    # first, assuming leaves are hash values in hex
    leaf = mapping.get(utils.from_hex(old))
    if leaf is None:
      leaf = mapping.get(hasher.hash_leaf(old))
      new = hasher.hash_leaf(new)
    # raise the error if the leaf's not found
    if not isinstance(leaf, MerkleNode):
      raise KeyError('Invalid old value.')
    leaf.hash = utils.from_hex(new)
    self._rehash(leaf)

  def append(self, item):
    """Appends a new leaf to the end of the tree.

    :param item: item to be added to the tree.
    Note: this will hash the item!
    """
    mapping, hasher, leaves, root = (
      self._mapping,
      self._hasher,
      self.leaves,
      self._root
    )
    # build first merkle root
    if len(leaves) == 0:
      root = MerkleNode(hasher.hash_leaf(item))
      mapping[root.hash] = root
      self._set_root(root)
      return

    last = leaves[-1]
    new_hash = hasher.hash_leaf(item)
    node = mapping[new_hash] = MerkleNode(new_hash)
    # only one leaf is present
    if last is root:
      root = MerkleNode.combine(hasher, root, node)
      self._set_root(root)
      return

    sibiling = last.sibiling
    connector = last.parent
    # replace _empty with a real node
    if sibiling is _empty:
      node.parent = connector
      connector.right = node
      self._rehash(node)
      return
    # build up a subtree until we find a node to which we can connect
    node.right = _empty
    while connector is not root:
      node = MerkleNode.combine(hasher, node, _empty)
      sibiling = connector.sibiling
      # we've found the node to which we can hook up the new subtree
      if sibiling is _empty:
        connector.parent.right = node
        node.parent = connector.parent
        self._rehash(node)
        return
      connector = connector.parent
    node = MerkleNode.combine(hasher, node, _empty)
    self._set_root(MerkleNode.combine(hasher, connector, node))

  def _set_root(self, new_root):
    # record the time when the root has been created/changed
    self._root = new_root
    self.last_changed = time.time()

  def extend(self, data):
    """Extends the tree by adding additional leaves.

    :param data: a collection of items to be appended to the tree.
    """
    if isinstance(data, MerkleTree):
      data = data.leaves
    elif not isinstance(data, collections.Iterable):
      data = (data, data)
    # traverse and append each item
    for item in data:
      self.append(item)

  @property
  def leaves(self):
    """Returns MerkleNode instances that
     represent the leaves of the tree."""
    return list(self._mapping.values())

  @property
  def hexleaves(self):
    """Returns the leaves of the tree as hexadecimal strings."""
    convert = lambda n: utils.to_hex(n.hash)
    return list(map(convert, self._mapping.values()))

  @property
  def merkle_root(self):
    root = self._root
    if root is None:
      return None
    return utils.to_hex(root.hash)

  @property
  def hasher(self):
    return self._hasher

  @hasher.setter
  def hasher(self, hashobj):
    # hashobj should be either a callable or Hasher
    if not isinstance(hashobj, Hasher):
      if not callable(hashobj):
        raise TypeError('Hash function should be callable.')
      hashobj = Hasher(hashobj)
    self._hasher = hashobj

  def verify_leaf_inclusion(self, target, proof):
    """Verifies that a tree includes a leaf.
    :param target: a leaf which is represented by either a real object
      (int, str, etc.) or the hash value of that object.
    :param proof: a data structure that contains
      AuditNode objects which serve to recreate the original Merkle hash root.
    :return: True if the leaf is included in the tree.
    """
    return verify_leaf_inclusion(
      target,
      proof,
      self._hasher,
      self.merkle_root
    )

  def clear(self):
    # clear all nodes and leaves
    self._root = None
    self._mapping.clear()

  def __len__(self):
    """Returns the number of leaves in the tree."""
    return len(self._mapping)

  def __eq__(self, other):
    """Checks if the trees are identical."""
    root_hash = self._root.hash
    if isinstance(other, MerkleTree):
      other_root_hash = utils.from_hex(other.merkle_root)
    else:
      other = utils.to_string(other)
      other_root_hash = utils.from_hex(other)
    return root_hash == other_root_hash

  def __ge__(self, other):
    """Verifies that the tree contains the same nodes
     and in the same order as the given tree/subtree.

    :param other: Merkle tree which is thought
      to be an older version of the current tree.
    :return: True if both the old and new trees are consistent.
    """
    return verify_tree_consistency(
      self,
      other.merkle_root,
      len(other)
    )

  def __repr__(self):
    return f'<{self.__class__.__name__}[{self.merkle_root}]>'

  def __str__(self):
    return repr(self)
