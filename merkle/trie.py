# -*- coding: future_fstrings -*-
import hashlib
import collections
import abc
import six
import functools


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
  raise TypeError('Invalid type')


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


@six.add_metaclass(abc.ABCMeta)
class _BaseNode(object):
  __slots__ = ('hash', 'type',)

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


class AuditProof(_BaseNode):
  def __init__(self, hash, type):
    self.hash = hash
    self.type = type


class MerkleTree(object):
  def __init__(self, leaves, hash_algo=None):
    if not leaves:
      raise TypeError('Invalid leaves param')
    self._init_hash_algo(hash_algo)
    self._build_tree(leaves)

  def _init_hash_algo(self, hash_algo):
    if hash_algo is None:
      hash_algo = _default_hash
    elif not callable(hash_algo):
      raise TypeError('hash should be a callable')
    self.hash_algo = hash_algo

  def _build_tree(self, leaves):
    self.mapping = self.root = None
    hash = self.hash_algo
    nodes = [MerkleNode(hash(leaf)) for leaf in leaves]
    leaves = list(nodes)
    while len(nodes) > 1:
      if (len(nodes) % 2) != 0:
        nodes.append(nodes[-1])
      nodes = [MerkleNode(hash(_concat(l, r)), l, r) for l, r in _pairwise(nodes)]
      leaves.extend(nodes)
    if len(leaves) > 0:
      self.mapping = { node.hash:node for node in leaves }
      self.root = nodes[0]

  def get_proof(self, leaf):
    mapping, hash = self.mapping, self.hash_algo
    target = mapping.get(leaf, mapping.get(hash(leaf)))
    if not isinstance(target, MerkleNode):
      raise TypeError('Invalid leaf')
    root, proof = self.root, []
    while target is not root:
      sibiling = target.get_sibiling()
      audit_prf = AuditProof(sibiling.hash, sibiling.type)
      proof.append(audit_prf)
      target = target.parent
    return proof

  def verify(self, target, proof):
    hash = self.hash_algo
    proof = [hash(target)] + proof
    root = functools.reduce(lambda x,y: hash(_concat(x, y)), proof)
    return root == self.root.hash
