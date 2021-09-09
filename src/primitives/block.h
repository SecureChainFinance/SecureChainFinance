// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashWitnessMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 hashStateRoot; // qtum
    uint256 hashUTXORoot; // qtum
    // proof-of-stake specific fields
    COutPoint prevoutStake;
    std::vector<unsigned char> vchBlockSigDlgt; // The delegate is 65 bytes or 0 bytes, it can be added in the signature paramether at the end to avoid compatibility problems
    CBlockHeader()
    {
        SetNull();
    }

<<<<<<< HEAD
    SERIALIZE_METHODS(CBlockHeader, obj) {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot);
        if (obj.IsParticlVersion()) {
            READWRITE(obj.hashWitnessMerkleRoot);
        }
        READWRITE(obj.nTime, obj.nBits, obj.nNonce);
    }
=======
    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.hashStateRoot, obj.hashUTXORoot, obj.prevoutStake, obj.vchBlockSigDlgt); }
>>>>>>> project-a/time/qtumcore0.21

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashWitnessMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        hashStateRoot.SetNull(); // qtum
        hashUTXORoot.SetNull(); // qtum
        vchBlockSigDlgt.clear();
        prevoutStake.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

<<<<<<< HEAD
    bool IsParticlVersion() const
    {
        return nVersion == PARTICL_BLOCK_VERSION;
    }
=======
    uint256 GetHashWithoutSign() const;
>>>>>>> project-a/time/qtumcore0.21

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    virtual bool IsProofOfStake() const //qtum
    {
        return !prevoutStake.IsNull();
    }

    virtual bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }
    
    virtual uint32_t StakeTime() const
    {
        uint32_t ret = 0;
        if(IsProofOfStake())
        {
            ret = nTime;
        }
        return ret;
    }

    void SetBlockSignature(const std::vector<unsigned char>& vchSign);
    std::vector<unsigned char> GetBlockSignature() const;

    void SetProofOfDelegation(const std::vector<unsigned char>& vchPoD);
    std::vector<unsigned char> GetProofOfDelegation() const;

    bool HasProofOfDelegation() const;

    CBlockHeader& operator=(const CBlockHeader& other) //qtum
    {
        if (this != &other)
        {
            this->nVersion       = other.nVersion;
            this->hashPrevBlock  = other.hashPrevBlock;
            this->hashMerkleRoot = other.hashMerkleRoot;
            this->nTime          = other.nTime;
            this->nBits          = other.nBits;
            this->nNonce         = other.nNonce;
            this->hashStateRoot  = other.hashStateRoot;
            this->hashUTXORoot   = other.hashUTXORoot;
            this->vchBlockSigDlgt    = other.vchBlockSigDlgt;
            this->prevoutStake   = other.prevoutStake;
        }
        return *this;
    }
};

/**
    see GETHEADERS message, vtx collapses to a single 0 byte
*/
class CBlockGetHeader : public CBlockHeader
{
    public:
        CBlockGetHeader() {};
        CBlockGetHeader(const CBlockHeader &header) { *((CBlockHeader*)this) = header; };
        std::vector<CTransactionRef> vtx;
        SERIALIZE_METHODS(CBlockGetHeader, obj)
        {
            READWRITEAS(CBlockHeader, obj);
            READWRITE(obj.vtx);
        }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // pos block signature - signed by one of the coin stake txout[N]'s owner
    std::vector<uint8_t> vchBlockSig;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    bool IsProofOfStake() const
    {
        return (vtx.size() > 0 && vtx[0]->IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
        if (obj.nVersion == PARTICL_BLOCK_VERSION) {
            READWRITE(obj.vchBlockSig);
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const //qtum
    {
        return IsProofOfStake()? std::make_pair(prevoutStake, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }
    
    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
<<<<<<< HEAD
        block.nVersion              = nVersion;
        block.hashPrevBlock         = hashPrevBlock;
        block.hashMerkleRoot        = hashMerkleRoot;
        block.hashWitnessMerkleRoot = hashWitnessMerkleRoot;
        block.nTime                 = nTime;
        block.nBits                 = nBits;
        block.nNonce                = nNonce;
=======
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.hashStateRoot  = hashStateRoot; // qtum
        block.hashUTXORoot   = hashUTXORoot; // qtum
        block.vchBlockSigDlgt    = vchBlockSigDlgt;
        block.prevoutStake   = prevoutStake;
>>>>>>> project-a/time/qtumcore0.21
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
