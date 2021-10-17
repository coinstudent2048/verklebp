# Merkle Tree
# Source: Section 2.2 of https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf

import dumb25519


class MerkleTree:
    def __init__(self, datablocks):
        self.datablocks = datablocks
        self.merkletreehashes = []
        self.merkleRoot = None

    def hashAllBlocks(self):
        blockhashes = [str(dumb25519.hash_to_scalar(block)) for block in self.datablocks]
        return blockhashes

    def buildMerkleTree(self, printAllHash=False):
        blockhashes = self.hashAllBlocks()
        self.merkletreehashes = [blockhashes]
        while len(blockhashes) > 1:
            cache = []
            for i in range(0, len(blockhashes), 2):
                try:
                    blockhashes[i + 1]
                except:  # if the last index of the hash is odd
                    cache.append(blockhashes[i])
                else:
                    cache.append(str(dumb25519.hash_to_scalar(blockhashes[i], blockhashes[i + 1])))
            self.merkletreehashes.append([cache])
            blockhashes = cache

        self.merkleRoot = blockhashes[0]
        print(f'The Merkle Root is: {self.merkleRoot}\n')

        if printAllHash == True:
            for i in range(len(self.merkletreehashes)):
                print(f'Level {i+1} of hash is: {self.merkletreehashes[i]}')
            print('')

    def vertifyMerkleTree(self, blockHash, vertificationHash):
        cache = blockHash
        for i in range(len(vertificationHash)):
            cache = str(dumb25519.hash_to_scalar(cache, vertificationHash[i]))

        if cache == self.merkleRoot:
            print(f'Verified! the Merkle Root is : {cache}\n')
        else:
            print(f'ERROR: Data is corrupted. The expected Merkle Root is : {self.merkleRoot}. Instead got : {cache}')

    def requestMerkleRoot(self):
        if self.merkleRoot == None:
            self.buildMerkleTree()
            return self.merkleRoot
        else:
            return self.merkleRoot

    def requestData(self, hash):
        for i in range(len(self.merkletreehashes[0])):
            if self.merkletreehashes[0][i] == hash:
                print(f'Data is found : {self.datablocks[i]}')
                return self.datablocks[i]
        print('ERROR: Data is not found')



if __name__ == '__main__':
    data = ['1012033', '623194', '23123912', '821988', '053853', '231', '745745', '942721']  # sample data for testing (even number of data)
    data2 = ['12312', '437', '132423']  # sample data for testing (odd number of data)

    # run with even number of data set
    print('Even Number Run')
    merkledata = MerkleTree(data)
    merkledata.buildMerkleTree(printAllHash=True)

    merkledata.vertifyMerkleTree('4936f3b0bd7b62b2816d4ba3704b7c09fd9a02a4f90240c584241e2a99203b0e',
    ['929f61d902302b88359ec0ed272b887bd2d087966ec5a333309a5c94cd5a470f', '3b4180187f6f2fed612a475490f977a8135d6b84214f5434f2685753b47b490e',
     '0f868e079c8ea2ff6a80e62507a0a721212abe6e30d684531ae7066e426e9a0f'])

    print(f'Request for the Merkle Root : {merkledata.requestMerkleRoot()}\n')

    merkledata.requestData('4936f3b0bd7b62b2816d4ba3704b7c09fd9a02a4f90240c584241e2a99203b0e')

    # run with odd number of data set
    print('\n\nOdd Number Run')
    merkledata = MerkleTree(data2)
    merkledata.buildMerkleTree(printAllHash=True)

    merkledata.vertifyMerkleTree('1efaeabe8be4f0f46d83643f2fe995f915cee16563bcf66cca561a26eadfb708',
    ['631846c8f24e90ee87477d4ea574635f882579691304c1cc1fee3c0a374bdd01', '183d43e18b39e3cbcfae6b2ed4716097ae019200d86fe1c0aa9e47c6bd605805',])

    merkledata.requestData('183d43e18b39e3cbcfae6b2ed4716097ae019200d86fe1c0aa9e47c6bd605805')
