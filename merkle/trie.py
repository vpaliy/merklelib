# -*- coding: future_fstrings -*-
import hashlib


def _default_hash(x):
  if isinstance(x, str):
    x = x.encode()
  return hashlib.sha256(x).hexdigest()


def _pairwise(iterable):
  a = iter(iterable)
  return zip(a, a)


class MerkleNode(object):
  __slots__ = ('hash', 'left', 'right', 'parent')

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

  def __eq__(self, other):
    return all([
      isinstance(other, MerkleNode),
      self.hash == other.hash
    ])

  def __hash__(self):
    return self.hash

  def __add__(self, other):
    if not isinstance(other, MerkleNode):
      raise TypeError('Invalid argument')
    return str(self.hash) + str(other.hash)

  def get_sibiling(self):
    parent = self.parent
    if parent is None:
      return None
    if parent.left is self:
      return parent.right
    elif parent.right is self:
      return parent.left
    return None

  def __repr__(self):
    return f'<MerkleNode {self.hash}>'


class MerkleTree(object):
  def __init__(self, leaves, hash_algo=None):
    if not leaves:
      raise TypeError('Invalid leaves param')
    self._init_hash_algo(hash_algo)
    self.leaves = leaves
    self.mapping = {}
    self.root = None
    self._build_tree(leaves)

  def _init_hash_algo(self, hash_algo):
    if hash_algo is None:
      hash_algo = _default_hash
    elif not callable(hash_algo):
      raise TypeError('hash should be a callable')
    self.hash_algo = hash_algo

  def _build_tree(self, leaves):
    hash = self.hash_algo
    nodes = [MerkleNode(hash(leaf)) for leaf in leaves]
    leaves = list(nodes)
    while len(nodes) > 1:
      if (len(nodes) % 2) != 0:
        nodes.append(nodes[-1])
      nodes = [MerkleNode(hash(l+r), l, r) for l, r in _pairwise(nodes)]
      leaves.extend(nodes)
    self.mapping = { node.hash:node for node in leaves }
    self.root = nodes[0]

  def get_proof(self, leaf):
    mapping, hash = self.mapping, self.hash_algo
    target = mapping.get(leaf, mapping.get(hash(leaf)))
    if not isinstance(target, MerkleNode):
      raise TypeError('Invalid leaf or hash')
    root, proof = self.root, []
    proof.append(target.hash)
    while target is not root:
      sibiling = target.get_sibiling()
      proof.append(sibiling.hash)
      target = target.parent
    return proof
