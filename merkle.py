# Merkle Tree
# Source: Section 2.2 of https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf
#
# unoptimized

from dumb25519 import Scalar, Point, ScalarVector, PointVector
import dumb25519

class MerkleTree:
    def __init__(self, datablocks):
        datalength = len(datablocks)
        if datalength & (datalength - 1) != 0 or datalength <= 0:   # check if not power of two
            raise ValueError('length of datablocks not a power of 2')
        self.datablocks = datablocks
        self.merkletreehashes = []

    def hashAllBlocks(self) -> list:
        blockhashes = [dumb25519.hash_to_scalar(block) for block in self.datablocks]
        return blockhashes

    def buildMerkleTree(self, printAllHash=False) -> Scalar:
        blockhashes = self.hashAllBlocks()
        self.merkletreehashes = [blockhashes]
        while len(blockhashes) > 1:
            cache = []
            for i in range(0, len(blockhashes), 2):
                cache.append(dumb25519.hash_to_scalar(blockhashes[i], blockhashes[i + 1]))
            self.merkletreehashes.append(cache)
            blockhashes = cache

        if printAllHash == True:
            for i, hashes in enumerate(self.merkletreehashes):
                print(f'Level {i + 1} of tree is: {hashes}')

        return blockhashes[0]   # return merkle tree root

    def requestData(self, index: int) -> list:
        num_blocks = len(self.datablocks)
        num_levels = len(self.merkletreehashes)
        if not(0 <= index < num_blocks):
            raise ValueError(f'index must be in range({num_blocks})')

        datum = self.datablocks[index]
        hashes = []
        for i in range(num_levels - 1):
            hashes.append(self.merkletreehashes[i][index ^ 1])
            index >>= 1
        return datum, hashes

def verifier(index: int, datum: object, hashes: list, root: Scalar) -> bool:
    curr = dumb25519.hash_to_scalar(datum)
    for hash in hashes:
        hash_index = index ^ 1
        if hash_index > index:
            curr = dumb25519.hash_to_scalar(curr, hash)
        else:
            curr = dumb25519.hash_to_scalar(hash, curr)
        index >>= 1
    return curr == root
    
if __name__ == '__main__':
    # len(data) should be a power of 2
    data = ['1017043', '623194', '28163912', '821988', '053853', '231', '745745', '942721']

    merkledata = MerkleTree(data)
    root = merkledata.buildMerkleTree(printAllHash=True)
    datum, hashes = merkledata.requestData(4)   # request for data[4]
    print(f'\ndata[4]: {datum}')
    print(f'provided hashes: {hashes}')

    # verify provided hashes
    if verifier(4, datum, hashes, root):
        print('\nProvided hashes are correct!')
    else:
        print('\nProvided hashes are wrong!')