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

from anytree import AnyNode, RenderTree
from anytree.exporter import DotExporter, JsonExporter

LEFT, RIGHT, ROOT = tuple(range(3))


def _default_hash(x):
  if isinstance(x, str):
    x = x.encode()
  return hashlib.sha256(x).hexdigest()


def _pairwise(iterable):
  a = iter(iterable)
  return zip(a, a)


def _get_hash(obj):
  if isinstance(obj, _BaseNode):
    return str(obj.hash)
  elif isinstance(obj, str):
    return obj
  raise TypeError('Object must be a an instance of _BaseNode or str')


def _get_printable_tree(tree):
  if not isinstance(tree, (MerkleTree, MerkleNode)):
    raise TypeError(
      f'Expected MerkleTree or MerkleNode, got {type(tree)}'
    )
  root = tree
  if isinstance(tree, MerkleTree):
    root = tree.root
  parent = AnyNode(name=root.hash)
  queue = [(root, parent)]
  while len(queue) > 0:
    node, par = queue.pop()
    left, right = node.left, node.right
    if left is not None:
      queue.append((left, AnyNode(name=left.hash, parent=par)))
    if right is not None:
      queue.append((right, AnyNode(name=right.hash, parent=par)))
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


def _concat(*nodes):
  def __concat(x, y):
    sum = lambda x, y: _get_hash(x) + _get_hash(y)
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
  leaves = tree.leaves()
  index, paths = 0, []
  while m > 0:
    level = 2 ** (m.bit_length() - 1)
    node = _climb_to(leaves[index], math.log(level, 2))
    if node is None:
      return False
    paths.append(node)
    index += level
    m -= level
  paths = paths[::-1]
  hash = tree.hash_algo
  if len(paths) > 1:
    # order is important !
    concat = lambda a,b: hash(_concat(b, a))
    new_root = functools.reduce(concat, paths)
  else:
    new_root = hash(paths[0])
  return new_root == root


def verify_node(target_hash, proof, hash_algo, root):
  if not callable(hash_algo):
    raise TypeError(f'Expected callable, got {type(hash_algo)}')
  proof = [target_hash] + proof
  res = functools.reduce(lambda x,y: hash_algo(_concat(x, y)), proof)
  return root == res


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
    if left is not None:
      left.parent = self
    if right is not None:
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
      return ROOT
    return LEFT if (parent.left is self) else RIGHT

  @classmethod
  def combine(cls, left, right, hash):
    return cls(hash(_concat(left, right)), left, right)


class AuditProof(_BaseNode):
  def __init__(self, hash, type):
    self.hash = hash
    self.type = type


class _EmptyNode(_BaseNode):
  __slots__ = ('parent', )

  def __init__(self, hash, parent=None):
    self.hash = hash
    self.parent = parent

  @property
  def type(self):
    # AttributeError if the tree has been modifed manually
    if self.parent.left is self:
      return LEFT
    return RIGHT

  @classmethod
  def from(cls, node):
    if not isinstance(node, MerkleNode):
      raise TypeError(f'Expected MerkleNode, got {type(node)}')
    return cls(node.hash, node.parent)


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
    self.hash_algo = hash_algo

  def _build_tree(self, leaves):
    self._mapping = self.root = None
    hash = self.hash_algo
    nodes = [MerkleNode(hash(leaf)) for leaf in leaves]
    leaves = list(nodes)
    while len(nodes) > 1:
      if (len(nodes) % 2) != 0:
        nodes.append(_EmptyNode.from(nodes[-1]))
      nodes = [MerkleNode.combine(l, r, hash) for l, r in _pairwise(nodes)]
    if len(leaves) > 0:
      self._mapping = { node.hash:node for node in leaves }
      self.root = nodes[0]

  def get_proof(self, leaf):
    mapping, hash = self._mapping, self.hash_algo
    target = mapping.get(leaf, mapping.get(hash(leaf)))
    if not isinstance(target, MerkleNode):
      raise ValueError('Invalid leaf')
    root, proof = self.root, []
    while target is not root:
      sibiling = target.get_sibiling()
      audit_prf = AuditProof(sibiling.hash, sibiling.type)
      proof.append(audit_prf)
      target = target.parent
    return proof

  def add(self, item):
    '''
      Even:
      - no additional nodes needed
      - node-sibiling-parent-hash

      Odd:
      - duplicate the added node
      - recursively rebuild the tree
    '''
    hash, last = self.hash_algo, self._last
    node = MerkleNode(hash(item))
    self._mapping[item] = node
    if len(self._mapping) % 2 == 0:
      parent = last.parent
      if parent.right is not last:
        raise RuntimeError(
          'Tree is invalid. It may have been modifed manually.'
        )
      parent.right = node
      node.parent = parent
    #  self._rehash(node)
    else:
      expand = _is_power(len(self._mapping) +  1)
      nodes = [MerkleNode(hash(_concat(node+node)), node, node)]
      while len(nodes) > 1:
        if expand:
          nodes.append(nodes[-1])
        nodes = [MerkleNode.combine(l, r, hash) for l, r in _pairwise(nodes)]

  @property
  def leaves(self):
    return self._mapping.values()

  def verify(self, target_hash, proof):
    root, hash = self.root.hash, self.hash_algo
    return verify_node(target_hash, proof, hash, root)

  def __eq__(self, other):
    hash, count = other.root.hash, len(other._mapping)
    return verify_tree(self, hash, count)
