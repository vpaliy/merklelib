# -*- coding: future_fstrings -*-
import argparse
import logging
import gc
import sys
from time import time

from merklelib import MerkleTree

logger = logging.Logger('merklelib-benchmark')


def getsize(obj):
  seen, queue, size = set(), [obj], 0
  while queue:
    seen.add(id(obj))
    size += sum(map(sys.getsizeof, queue))
    for ref in gc.get_referents(*queue):
      if id(ref) not in seen and not isinstance(ref, type):
        seen.add(id(ref))
        queue.append(ref)
  return size


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
    '-s', '--size',
    help='Initial number of leaves',
    dest='size',
    default=2 ** 14
  )

  parser.add_argument(
    '-a', '--additional',
    help='Number of leaves that we need to append',
    dest='additional',
    default=2 ** 4
  )

  args = parser.parse_args()
  start, end = args.size, args.additional

  start_t = time()

  tree = MerkleTree(value for value in range(start))

  logger.info(f'Building: {time() - start_t} milliseconds.')
  start_t = time()

  # appending
  for v in range(start, end):
    tree.append(v)

  logger.info(f'Appending: {time() - start_t} milliseconds.')
  logger.info(f'Tree size: {getsize(tree)}')
  start_t = time()

  for leaf in range(end):
    proof = tree.get_proof(leaf)
    if not tree.verify(leaf, proof):
      logger.error(f'Failed audit proof: {leaf}')

  logger.info(f'Audit proof verification: {time() - start_t} milliseconds.')
  start_t = time()

  for limit in range(1, end):
    test = MerkleTree([value for value in range(limit)])
    if not (tree == test):
      logger.info(f'Failed consistency proof: {limit}')

  logger.info(f'Consistency proof verification: {time() - start_t} milliseconds.')

if __name__ == '__main__':
  main()
