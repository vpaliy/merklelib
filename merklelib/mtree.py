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

from anytree import AnyNode, RenderTree
from anytree.exporter import DotExporter, JsonExporter

LEFT, RIGHT, UNKNOWN = tuple(range(3))

_empty = object()


def _default_hash(x):
  if isinstance(x, str):
    x = x.encode()
  return hashlib.sha256(x).hexdigest()


def _pairwise(iterable):
  a = iter(iterable)
  return zip(a, a)


def is_power(n):
  return ((n & (n - 1)) == 0) and n != 0


def _get_hash(obj):
  if isinstance(obj, _BaseNode):
    return str(obj.hash)
  elif isinstance(obj, str):
    return obj
  raise TypeError(
    'Object must be a an instance of _BaseNode or str'
    f' got {type(obj)}'
  )


def _get_printable_tree(tree):
  if not isinstance(tree, (MerkleTree, MerkleNode)):
    raise TypeError(
      f'Expected MerkleTree or MerkleNode, got {type(tree)}'
    )
  root = tree
  if isinstance(tree, MerkleTree):
    root = tree._root
  parent = AnyNode(name=root.hash)
  queue = [(root, parent)]
  while len(queue) > 0:
    node, par = queue.pop()
    left, right = node.left, node.right
    if left is not None:
      queue.append((left, AnyNode(name=left.hash, parent=par)))
    if (right is not None) and (right is not _empty):
      any_node = AnyNode(name=right.hash, parent=par)
      queue.append((right, any_node))
  return parent


def export(tree, filename, ext='json', **kwargs):
  parent = _get_printable_tree(tree)
  if ext == 'json':
    with io.open(f'{filename}.json', mode='w+', encoding='utf-8') as fp:
      JsonExporter(**kwargs).write(parent, fp)
  else:
    DotExporter(parent, **kwargs).to_picture(f'{filename}.{ext}')


def jsonify(tree, **kwargs):
  parent = _get_printable_tree(tree)
  return JsonExporter(**kwargs).export(parent)


def beautify(tree):
  parent = _get_printable_tree(tree)
  for pre, fill, node in RenderTree(parent):
    print(f'{pre}{node.name}')


def _concat(hash, *nodes):
  def __concat(x, y):
    if (x is _empty) or (y is _empty):
      return x.hash if y is _empty else y.hash
    sum = lambda x, y: hash(_get_hash(x) + _get_hash(y))
    if isinstance(x, _BaseNode):
      if x.type == LEFT:
        return sum(x, y)
      elif x.type == RIGHT:
        return sum(y, x)
    if isinstance(y, _BaseNode):
      if y.type == LEFT:
        return sum(y, x)
    return sum(x, y)
  return functools.reduce(__concat, nodes)


def _climb_to(node, level):
  while (level > 0) and node:
    level -= 1
    node = node.parent
  return node


def verify_tree(tree, root, m):
  if not isinstance(tree, MerkleTree):
    raise TypeError(f'Expected MerkleTree, got {type(tree)}')
  if len(tree) < m:
    return False
  leaves = tree.leaves
  index, paths = 0, []
  while m > 0:
    level = 2 ** (m.bit_length() - 1)
    node = _climb_to(leaves[index], math.log(level, 2))
    if node is None:
      return False
    paths.append(node)
    index += level
    m -= level
  if len(paths) > 1:
    paths = paths[::-1]
    # order is important !
    concat = lambda a,b: _concat(tree.algo, b, a)
    new_root = functools.reduce(concat, paths)
  else:
    new_root = paths[0].hash
  return new_root == root


def verify_node(target, proof, hash_algo, root):
  if not callable(hash_algo):
    raise TypeError(f'Expected callable, got {type(hash_algo)}')
  # keep it dry
  concat = lambda x,y: _concat(hash_algo, x, y)
  def _calculate_root(target):
    _proof = [target] + proof
    return functools.reduce(concat, _proof)

  new_root = _calculate_root(target)
  # try again if the user forgot to hash the target
  if new_root != root:
    try:
      new_root = _calculate_root(hash_algo(target))
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
    if (left is not None) and (left is not _empty):
      left.parent = self
    if (right is not None) and (right is not _empty):
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
  def combine(cls, left, right, hash):
    return cls(_concat(hash, left, right), left, right)


class AuditProof(_BaseNode):
  def __init__(self, hash, type):
    self.hash = hash
    self.type = type


class MerkleTree(object):
  def __init__(self, leaves, hash_algo=None):
    if not leaves:
      raise ValueError('Invalid leaves param')
    self._init_hash_algo(hash_algo)
    self._build_tree(leaves)

  def _init_hash_algo(self, hash_algo):
    if hash_algo is None:
      hash_algo = _default_hash
    elif not callable(hash_algo):
      raise TypeError('hash must be a callable')
    self._hash_algo = hash_algo

  def _build_tree(self, leaves):
    self._mapping = self._root = None
    hash = self._hash_algo
    nodes = [MerkleNode(hash(leaf)) for leaf in leaves]
    leaves = list(nodes)
    while len(nodes) > 1:
      if (len(nodes) % 2) != 0:
        nodes.append(_empty)
      nodes = [MerkleNode.combine(l, r, hash) for l, r in _pairwise(nodes)]
    if len(leaves) > 0:
      mapping = collections.OrderedDict()
      for leaf in leaves:
        mapping[leaf.hash] = leaf
      self._mapping = mapping
      self._set_root(nodes[0])

  def get_proof(self, leaf):
    mapping, hash = self._mapping, self._hash_algo
    target = mapping.get(leaf, mapping.get(hash(leaf)))
    if not isinstance(target, MerkleNode):
      return []
    root, proof = self._root, []
    while target is not root:
      sibiling = target.get_sibiling()
      if sibiling is not _empty:
        audit_prf = AuditProof(sibiling.hash, sibiling.type)
        proof.append(audit_prf)
      target = target.parent
    return proof

  def _rehash(self, node):
    root, hash = self._root, self._hash_algo
    # rehash all the nodes to the root
    while node is not root:
      parent = node.parent
      sibiling = node.get_sibiling()
      parent.hash = _concat(hash, node, sibiling)
      node = parent

  def update(self, old, new):
    if type(old) != type(new):
      raise TypeError(
        'Old and the new value are of different types.'
        'You should hash them to avoid the exception.'
      )
    mapping, hash = self._mapping, self._hash_algo
    leaf = mapping.get(old)
    if leaf is None:
      leaf = mapping.get(hash(old))
      new = hash(new)
    if not isinstance(leaf, MerkleNode):
      raise KeyError('Invalid old value.')
    leaf.hash = new
    self._rehash(leaf)

  def _add(self, item):
    mapping, hash, leaves, root = (
      self._mapping,
      self._hash_algo,
      self.leaves,
      self._root
    )
    last = leaves[-1]
    new_hash = hash(item)
    node = mapping[new_hash] = MerkleNode(new_hash)

    if last is root:
      root = MerkleNode.combine(root, node, hash)
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
      node = MerkleNode.combine(node, _empty, hash)
      sibiling = connector.get_sibiling()
      if sibiling is _empty:
        connector.parent.right = node
        node.parent = connector.parent
        self._rehash(node)
        return
      connector = connector.parent

    node = MerkleNode.combine(node, _empty, hash)
    self._set_root(MerkleNode.combine(connector, node, hash))

  def _set_root(self, new_root):
    self._root = new_root
    self.last_changed = time.time()

  def add(self, item):
    leaves = item
    if isinstance(item, MerkleTree):
      leaves = item.leaves
    elif (isinstance(item, str) or
        not isinstance(item, collections.Iterable)):
      leaves = (item, )

    for leaf in leaves:
      self._add(leaf)

  @property
  def leaves(self):
    return list(self._mapping.values())

  @property
  def merkle_root(self):
    if self._root is None:
      return None
    return self._root.hash

  @property
  def algo(self):
    return self._hash_algo

  @algo.setter
  def algo(self, hash_algo):
    self._init_hash_algo(hash_algo)

  def verify(self, target, proof):
    return verify_node(
      target,
      proof,
      self.algo,
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
