# Merkle Tree
# Source: Section 2.2 of https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf

import hashlib


class MerkleTree:
    def __init__(self, datablocks):
        self.datablocks = datablocks
        self.datablockhashes = []
        self.toplevelhash = []

    def hashAllBlocks(self):
        for block in self.datablocks:
            self.toplevelhash.append(hashlib.sha256(block.encode('ascii')).hexdigest())

    def findMerkleTree(self, printAllHash=False):
        self.hashAllBlocks()
        self.datablockhashes = [self.toplevelhash]
        while len(self.toplevelhash) > 1:
            cache = []
            for i in range(0, len(self.toplevelhash), 2):
                try:
                    self.toplevelhash[i + 1]
                except:  # if the last index of the toplevelhash is odd
                    cache.append(self.toplevelhash[i])
                else:
                    cache.append(hashlib.sha256(self.toplevelhash[i].encode('ascii') + self.toplevelhash[i + 1].encode('ascii')).hexdigest())
            self.datablockhashes.append([cache])
            self.toplevelhash = cache
        print(f'The Merkle Tree Hash is: {self.toplevelhash}\n')

        if printAllHash == True:
            for i in range(len(self.datablockhashes)):
                print(f'Level {i+1} of hash is: {self.datablockhashes[i]}')


if __name__ == '__main__':
    data = ['1012033', '623194', '23123912', '821988', '053853', '231', '745745', '942721']  # sample data for testing (even number of data)
    data2 = ['12312', '437', '132423']  # sample data for testing (odd number of data)

    # run with even number of data set
    print('Even Number Run')
    merkledata = MerkleTree(data)
    merkledata.findMerkleTree(printAllHash=True)

    # run with odd number of data set
    print('\n\nOdd Number Run')
    merkledata = MerkleTree(data2)
    merkledata.findMerkleTree(printAllHash=True)
