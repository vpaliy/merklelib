# -*- coding: future_fstrings -*-
from merklelib import utils
from merklelib.merkle import MerkleNode, MerkleTree, _BaseNode

from anytree import AnyNode, RenderTree
from anytree.exporter import DotExporter, JsonExporter


__all__ = ['beautify', 'export', 'jsonify']


def _get_printable_tree(tree):
  if not isinstance(tree, (MerkleTree, MerkleNode)):
    raise TypeError(
      f'Expected MerkleTree or MerkleNode, got {type(tree)}'
    )
  root = tree
  if isinstance(tree, MerkleTree):
    root = tree._root
  get_hash = lambda n: utils.to_hex(n.hash)
  parent = AnyNode(name=get_hash(root))
  queue = [(root, parent)]
  while len(queue) > 0:
    node, par = queue.pop()
    left, right = node.left, node.right
    if isinstance(left, _BaseNode):
      queue.append((left, AnyNode(name=get_hash(left), parent=par)))
    if isinstance(right, _BaseNode):
      any_node = AnyNode(name=get_hash(right), parent=par)
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
