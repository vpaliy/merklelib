# -*- coding: future_fstrings -*-
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import gc
import sys
from numbers import Number
from collections import Set, Mapping, deque
from datetime import datetime

try: # Python 2
    zero_depth_bases = (basestring, Number, xrange, bytearray)
    iteritems = 'iteritems'
except NameError: # Python 3
    zero_depth_bases = (str, bytes, Number, range, bytearray)
    iteritems = 'items'

from merklelib import MerkleTree, beautify


# Courtesy of Aaron Hall
# https://stackoverflow.com/questions/449560/how-do-i-determine-the-size-of-an-object-in-python
def getsize(obj_0):
  """Recursively iterate to sum size of object & members."""
  _seen_ids = set()
  def inner(obj):
    obj_id = id(obj)
    if obj_id in _seen_ids:
      return 0
    _seen_ids.add(obj_id)
    size = sys.getsizeof(obj)
    if isinstance(obj, zero_depth_bases):
      pass # bypass remaining control flow and return
    elif isinstance(obj, (tuple, list, Set, deque)):
      size += sum(sys.getsizeof(i) for i in obj)
    elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
      size += sum(inner(k) + inner(v) for k, v in getattr(obj, iteritems)())
    # Check for custom object instances - may subclass above too
    if hasattr(obj, '__dict__'):
      size += inner(vars(obj))
    if hasattr(obj, '__slots__'): # can have __slots__ with __dict__
      size += sum(inner(getattr(obj, s)) for s in obj.__slots__ if hasattr(obj, s))
    return size
  return inner(obj_0)


def _get_seconds(start):
  return (datetime.now() - start).total_seconds()


def _print_times(average, total, max_t, min_t):
  print(f' Average time: {average} seconds.')
  print(f' Total time: {total} seconds.')
  print(f' Longest time: {max_t} seconds.')
  print(f' Shortest time: {min_t} seconds.')


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
    '-s', '--size',
    help='Initial number of leaves',
    dest='size',
    default=2 ** 8
  )

  parser.add_argument(
    '-a', '--additional',
    help='Number of leaves that we need to append',
    dest='additional',
    default=2 ** 1
  )

  parser.add_argument(
    '-p', '--print',
    help='''
     Beautify the whole tree.
     Recommended to use when the size of the tree is less than 10.
     ''',
    action='store_true',
    dest='printable'
  )

  args = parser.parse_args()
  start, end = int(args.size), int(args.additional)
  count = start + end

  start_t = datetime.now()

  tree = MerkleTree(value for value in range(start))

  print(f'Building: {_get_seconds(start_t)} seconds.')
  start_t = datetime.now()

  # appending
  for v in range(start, start + end):
    tree.append(v)

  print(f'Appending: {_get_seconds(start_t)} seconds.')
  print(f'Tree size: {getsize(tree)}')
  print(f'Number of leaves: {len(tree)}')

  if args.printable:
    beautify(tree)

  start_t = datetime.now()

  total, start_t = 0.0, datetime.now()
  max_t = min_t = None
  for leaf in range(count):
    cycle_t = datetime.now()
    proof = tree.get_proof(leaf)
    if not tree.verify_leaf_inclusion(leaf, proof):
      exit(f'Failed audit proof: {leaf}')
    seconds = _get_seconds(cycle_t)
    if max_t is None:
      max_t = min_t = seconds
    else:
      max_t = max(max_t, seconds)
      min_t = min(min_t, seconds)
    total += seconds

  print(f'Audit proof verification times:')
  _print_times(
    average=(total / float(count)),
    total=_get_seconds(start_t),
    max_t=max_t,
    min_t=min_t
  )

  total, start_t = 0.0, datetime.now()
  max_t = min_t = None
  for limit in range(1, count):
    cycle_t = datetime.now()
    test = MerkleTree([value for value in range(limit)])
    if tree < test:
      exit(f'Failed consistency proof: {limit}')
    seconds = _get_seconds(cycle_t)
    if max_t is None:
      max_t = min_t = seconds
    else:
      max_t = max(max_t, seconds)
      min_t = min(min_t, seconds)
    total += seconds

  print(f'Consitency proof verification times ({count} trees):')
  _print_times(
    average=(total / float(count)),
    total=_get_seconds(start_t),
    max_t=max_t,
    min_t=min_t
  )


if __name__ == '__main__':
  main()
