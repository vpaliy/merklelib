# -*- coding: future_fstrings -*-
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

LEFT, RIGHT, UNKNOWN = tuple(range(3))
_empty = object()


def _default_hash(value):
  value = utils.to_string(value)
  return hashlib.sha256(value).hexdigest()


def _hash_from_hex(func):
  # keep it dry
  if hasattr(func, '_hex_decorator'):
    return func._hex_decorator
  @functools.wraps(func)
  def _wrapper(*args, **kwargs):
    hash_value = func(*args, **kwargs)
    return utils.from_hex(hash_value)
  func._hex_decorator = _wrapper
  return _wrapper


class Hasher(object):
  def __init__(self, hashfunc):
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
    return f'{self.__class__.__name__}({self._hashfunc})'

  def __str__(self):
    return repr(self)


def _pairwise(iterable):
  a = iter(iterable)
  return zip(a, a)


def _get_hash(obj):
  if isinstance(obj, _BaseNode):
    return utils.to_string(obj.hash)
  return utils.to_string(obj)


def _concat(hasher, *nodes):
  def __concat(x, y):
    if (x is _empty) or (y is _empty):
      return x.hash if y is _empty else y.hash
    children = (_get_hash(x), _get_hash(y))
    if isinstance(x, _BaseNode)and x.type == RIGHT:
      return hasher.hash_children(*children[::-1])
    if isinstance(y, _BaseNode) and y.type == LEFT:
      return hasher.hash_children(*children[::-1])
    return hasher.hash_children(*children)
  return functools.reduce(__concat, nodes)


def _climb_to(node, level):
  while (level > 0) and node:
    level -= 1
    node = node.parent
  return node


def verify_tree(tree, root, old_size):
  if not isinstance(tree, MerkleTree):
    raise TypeError(f'Expected MerkleTree, got {type(tree)}')

  new_size = len(tree)
  if new_size < old_size:
    return False

  root = utils.from_hex(root)
  new_root = utils.from_hex(tree.merkle_root)
  if new_size == old_size:
    return root == new_root

  leaves = tree.leaves
  index, paths = 0, []

  while old_size > 0:
    level = 2 ** (old_size.bit_length() - 1)
    node = _climb_to(leaves[index], math.log(level, 2))
    if node is None:
      return False
    paths.append(node)
    index += level
    old_size -= level

  if len(paths) > 1:
    paths = paths[::-1]
    # order is important !
    concat = lambda a,b: _concat(tree.hasher, b, a)
    new_root = functools.reduce(concat, paths)
  else:
    new_root = paths[0].hash

  return new_root == root


def verify_node(target, proof, hasher, root):
  if not isinstance(hasher, Hasher):
    if not callable(hasher):
      raise TypeError(f'Expected callable, got {type(hasher)}')
    hasher = Hasher(hashfunc=hasher)

  paths = None

  if isinstance(proof, collections.Iterable):
    if isinstance(proof[0], AuditNode):
      paths = proof
    elif utils.is_string(proof[0]):
      paths = [utils.from_hex(p) for p in proof]
  elif isinstance(proof, AuditProof):
    paths = proof._nodes
  if paths is None:
    raise TypeError(
      'Proof must be either <AuditProof>, '
      'a collection of <AuditNode> or hexadecimal strings.'
      )
  # keep it dry
  concat = lambda x,y: _concat(hasher, x, y)
  def _calculate_root(target):
    _proof = [target] + paths
    return functools.reduce(concat, _proof)

  new_root = _calculate_root(target)
  root = utils.from_hex(root)
  # try again if the user forgot to hash the target
  if new_root != root:
    try:
      new_root = _calculate_root(hasher.hash_leaf(target))
    except:
      pass
  return new_root == root


@six.add_metaclass(abc.ABCMeta)
class _BaseNode(object):
  __slots__ = ('hash', 'type',)

  def __init__(self, hash, type):
    self.hash = hash
    self.type = type

  def __eq__(self, other):
    return all([
      isinstance(other, _BaseNode),
      self.hash == other.hash
    ])

  def __repr__(self):
    name = type(self).__name__
    return f'<{name} {self.hash}>'


class MerkleNode(_BaseNode):
  __slots__ = ('left', 'right', 'parent',)

  def __init__(self, hash, left=None, right=None, parent=None):
    if not hash:
      raise TypeError('Invalid hash')
    self.hash = hash
    self.left = left
    self.right = right
    if left and (left is not _empty):
      left.parent = self
    if right and (right is not _empty):
      right.parent = self
    self.parent = parent

  def get_sibiling(self):
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
    return cls(_concat(hasher, left, right), left, right)


class AuditNode(_BaseNode):
  def __init__(self, hash, type):
    self.hash = hash
    self.type = type


class AuditProof(object):
  def __init__(self, nodes):
    self._nodes = nodes

  @property
  def hex_nodes(self):
    if not hasattr(self, '_hex_nodes'):
      self._hex_nodes = [
        utils.to_hex(n.hash) for n in self._nodes
      ]
    return self._hex_nodes

  def __repr__(self):
    items = ', '.join(self.hex_nodes)
    return f'{{ items }}'


class MerkleTree(object):
  def __init__(self, leaves, hashfunc=None):
    if not leaves:
      raise ValueError('Invalid leaves param')
    self._init_hashfunc(hashfunc)
    self._build_tree(leaves)

  def _init_hashfunc(self, hashfunc):
    if hashfunc is None:
      hashfunc = _default_hash
    elif not callable(hashfunc):
      raise TypeError('hash must be a callable')
    self._hasher = Hasher(hashfunc)

  def _build_tree(self, leaves):
    self._mapping = self._root = None
    hasher = self._hasher
    nodes = [MerkleNode(hasher.hash_leaf(leaf)) for leaf in leaves]
    leaves = list(nodes)
    while len(nodes) > 1:
      if (len(nodes) % 2) != 0:
        nodes.append(_empty)
      nodes = [MerkleNode.combine(hasher, l, r) for l, r in _pairwise(nodes)]
    if len(leaves) > 0:
      mapping = collections.OrderedDict()
      for leaf in leaves:
        mapping[leaf.hash] = leaf
      self._mapping = mapping
      self._set_root(nodes[0])

  def get_proof(self, leaf):
    mapping, hasher = self._mapping, self._hasher
    target = mapping.get(utils.from_hex(leaf))
    if target is None:
      target = mapping.get(hasher.hash_leaf(leaf))
    if not isinstance(target, MerkleNode):
      return AuditProof([])
    root, paths = self._root, []
    while target is not root:
      sibiling = target.get_sibiling()
      if sibiling is not _empty:
        node = AuditNode(sibiling.hash, sibiling.type)
        paths.append(node)
      target = target.parent
    return AuditProof(paths)

  def _rehash(self, node):
    root, hasher = self._root, self._hasher
    # rehash all the nodes to the root
    while node is not root:
      parent = node.parent
      sibiling = node.get_sibiling()
      parent.hash = _concat(hasher, node, sibiling)
      node = parent

  def update(self, old, new):
    if type(old) != type(new):
      raise TypeError(
        'Old and the new value are of different types.'
        'You should hash them to avoid the exception.'
      )
    mapping, hasher = self._mapping, self._hasher
    leaf = mapping.get(utils.from_hex(old))
    if leaf is None:
      leaf = mapping.get(hasher.hash_leaf(old))
      new = hasher.hash_leaf(new)
    if not isinstance(leaf, MerkleNode):
      raise KeyError('Invalid old value.')
    leaf.hash = utils.from_hex(new)
    self._rehash(leaf)

  def _append(self, item):
    mapping, hasher, leaves, root = (
      self._mapping,
      self._hasher,
      self.leaves,
      self._root
    )
    last = leaves[-1]
    new_hash = hasher.hash_leaf(item)
    node = mapping[new_hash] = MerkleNode(new_hash)

    if last is root:
      root = MerkleNode.combine(hasher, root, node)
      self._set_root(root)
      return

    sibiling = last.get_sibiling()
    connector = last.parent

    if sibiling is _empty:
      node.parent = connector
      connector.right = node
      self._rehash(node)
      return

    node.right = _empty
    while connector is not root:
      node = MerkleNode.combine(hasher, node, _empty)
      sibiling = connector.get_sibiling()
      if sibiling is _empty:
        connector.parent.right = node
        node.parent = connector.parent
        self._rehash(node)
        return
      connector = connector.parent

    node = MerkleNode.combine(hasher, node, _empty)
    self._set_root(MerkleNode.combine(hasher, connector, node))

  def _set_root(self, new_root):
    self._root = new_root
    self.last_changed = time.time()

  def append(self, item):
    leaves = item
    if isinstance(item, MerkleTree):
      leaves = item.leaves
    elif utils.is_string(item):
      leaves = (item, )
    elif not isinstance(item, collections.Iterable):
      leaves = (item, )

    for leaf in leaves:
      self._append(leaf)

  @property
  def leaves(self):
    return list(self._mapping.values())

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
  def hasher(self, hasher):
    if not isinstance(hasher, Hasher):
      if not callable(hasher):
        raise TypeError('Hash function should be callable.')
      hasher = Hasher(hashfunc=hasher)
    self._hasher = hasher

  def verify(self, target, proof):
    return verify_node(
      target,
      proof,
      self._hasher,
      self.merkle_root
    )

  def __len__(self):
    return len(self._mapping)

  def __eq__(self, other):
    return verify_tree(
      self,
      other.merkle_root,
      len(other)
    )

  def __repr__(self):
    return f'<MerkleTree {self.merkle_root}>'
