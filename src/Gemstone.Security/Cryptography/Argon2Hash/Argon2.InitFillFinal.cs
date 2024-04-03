// <copyright file="Argon2.InitFillFinal.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using System.Linq;
using System.Threading;
using Gemstone.ArrayExtensions;
using Gemstone.Security.Cryptography.Blake2BHash;

namespace Gemstone.Security.Cryptography.Argon2Hash;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    private void Initialize()
    {
        using ZeroedBuffer<byte> blockHash = new(PrehashSeedLength);
        using (ZeroedBuffer<byte> initialHash = InitialHash())
        {
            Array.Copy(initialHash.Buffer, blockHash.Buffer, PrehashDigestLength);
        }

        //InitialKat(blockHash.Buffer, this);
        FillFirstBlocks(blockHash.Buffer);
    }

    private ZeroedBuffer<byte> InitialHash()
    {
        ZeroedBuffer<byte> ret = new(Blake2B.OutputLength);
        
        using Hasher blakeHash = Blake2B.Create(new Blake2BConfig
        {
            OutputSizeInBytes = PrehashDigestLength,
            Result64ByteBuffer = ret.Buffer,
        });

        byte[] value = new byte[4];
        
        Store32(value, m_config.Lanes);
        blakeHash.Update(value);
        
        Store32(value, m_config.HashLength);
        blakeHash.Update(value);
        
        Store32(value, m_config.MemoryCost);
        blakeHash.Update(value);
        
        Store32(value, m_config.TimeCost);
        blakeHash.Update(value);
        
        Store32(value, (uint)m_config.Version);
        blakeHash.Update(value);
        
        Store32(value, (uint)m_config.Type);
        blakeHash.Update(value);
        
        Store32(value, m_config.Password?.Length ?? 0);
        blakeHash.Update(value);
        
        if (m_config.Password != null)
        {
            blakeHash.Update(m_config.Password);
            
            if (m_config.ClearPassword) 
                m_config.Password.Zero();
        }

        Store32(value, m_config.Salt?.Length ?? 0);
        blakeHash.Update(value);

        if (m_config.Salt != null)
        {
            blakeHash.Update(m_config.Salt);
        }

        Store32(value, m_config.Secret?.Length ?? 0);
        blakeHash.Update(value);

        if (m_config.Secret != null)
        {
            blakeHash.Update(m_config.Secret);
            if (m_config.ClearSecret)
                m_config.Secret.Zero();
        }

        Store32(value, m_config.AssociatedData?.Length ?? 0);
        blakeHash.Update(value);

        if (m_config.AssociatedData != null) 
            blakeHash.Update(m_config.AssociatedData);

        blakeHash.Finish();

        return ret;
    }

    private void FillFirstBlocks(byte[] blockHash)
    {
        using ZeroedBuffer<byte> blockHashBytes = new(BlockSize);

        for (int l = 0; l < m_config.Lanes; ++l)
        {
            Store32(blockHash, PrehashDigestLength, 0);
            Store32(blockHash, PrehashDigestLength + 4, l);
            Blake2BLong(blockHashBytes.Buffer, blockHash);
            LoadBlock(Memory[l * LaneBlockCount], blockHashBytes.Buffer);
            
            Store32(blockHash, PrehashDigestLength, 1);
            Blake2BLong(blockHashBytes.Buffer, blockHash);
            LoadBlock(Memory[l * LaneBlockCount + 1], blockHashBytes.Buffer);
        }
    }

    private void FillMemoryBlocks()
    {
        if (m_config.Threads > 1)
        {
            WaitHandle[] waitHandles = Enumerable.Range(0, m_config.Threads > m_config.Lanes ? m_config.Lanes : m_config.Threads)
                .Select(_ => new AutoResetEvent(false))
                .Cast<WaitHandle>()
                .ToArray();

            for (int passNumber = 0; passNumber < m_config.TimeCost; ++passNumber)
            {
                for (int sliceNumber = 0; sliceNumber < SyncPointCount; ++sliceNumber)
                {
                    int laneNumber = 0;
                    int remaining = m_config.Lanes;
                    
                    for (; laneNumber < waitHandles.Length && laneNumber < m_config.Lanes; ++laneNumber)
                    {
                        ThreadPool.QueueUserWorkItem(fs =>
                        {
                            FillSegment(((FillState)fs!).Position);
                            ((FillState)fs).Are.Set();
                        },
                        new FillState(new Position
                        {
                            Pass = passNumber, 
                            Lane = laneNumber, 
                            Slice = sliceNumber, 
                            Index = 0
                        }, (AutoResetEvent)waitHandles[laneNumber]));
                    }

                    while (laneNumber < m_config.Lanes)
                    {
                        int i = WaitHandle.WaitAny(waitHandles);
                        --remaining;
                        
                        ThreadPool.QueueUserWorkItem(fs =>
                        {
                            FillSegment(((FillState)fs!).Position);
                            ((FillState)fs).Are.Set();
                        },
                        new FillState(new Position
                        {
                            Pass = passNumber, 
                            Lane = laneNumber, 
                            Slice = sliceNumber, 
                            Index = 0
                        }, (AutoResetEvent)waitHandles[i]));
                        
                        ++laneNumber;
                    }

                    while (remaining > 0)
                    {
                        _ = WaitHandle.WaitAny(waitHandles);
                        --remaining;
                    }
                }

                //InternalKat(this, passNumber);
            }
        }
        else
        {
            for (int passNumber = 0; passNumber < m_config.TimeCost; ++passNumber)
                for (int sliceNumber = 0; sliceNumber < SyncPointCount; ++sliceNumber)
                    for (int laneNumber = 0; laneNumber < m_config.Lanes; ++laneNumber) 
                        FillSegment(new Position { Pass = passNumber, Lane = laneNumber, Slice = sliceNumber, Index = 0 });

                //InternalKat(this, passNumber);
        }
    }

    private ZeroedBuffer<byte> Final()
    {
        using ZeroedBuffer<ulong> blockHashBuffer = new(BlockSize / 8);
        BlockValues blockHash = new(blockHashBuffer.Buffer, 0);
        blockHash.Copy(Memory[LaneBlockCount - 1]);

        // XOR last blocks
        for (int l = 1; l < m_config.Lanes; ++l) 
            blockHash.Xor(Memory[l * LaneBlockCount + (LaneBlockCount - 1)]);

        using ZeroedBuffer<byte> blockHashBytes = new(BlockSize);
        StoreBlock(blockHashBytes.Buffer, blockHash);
        
        ZeroedBuffer<byte> ret = new(m_config.HashLength);
        Blake2BLong(ret.Buffer, blockHashBytes.Buffer);
        
        //PrintTag(ret.Buffer);
        
        return ret;
    }

    private void FillSegment(Position position)
    {
        bool dataIndependentAddressing = m_config.Type == Argon2Type.DataIndependentAddressing || (m_config.Type == Argon2Type.HybridAddressing && position is { Pass: 0, Slice: < SyncPointCount / 2 });
        ulong[] pseudoRands = new ulong[SegmentBlockCount];
        
        if (dataIndependentAddressing) 
            GenerateAddresses(position, pseudoRands);

        // 2 if already generated the first two blocks
        int startingIndex = position is { Pass: 0, Slice: 0 } ? 2 : 0;
        int curOffset = position.Lane * LaneBlockCount + position.Slice * SegmentBlockCount + startingIndex;
        int prevOffset = curOffset % LaneBlockCount == 0 ? curOffset + LaneBlockCount - 1 : curOffset - 1;

        for (int i = startingIndex; i < SegmentBlockCount; ++i, ++curOffset, ++prevOffset)
        {
            if (curOffset % LaneBlockCount == 1) 
                prevOffset = curOffset - 1;

            // compute index of reference block taking pseudo-random value from previous block
            ulong pseudoRand = dataIndependentAddressing ? pseudoRands[i] : Memory[prevOffset][0];

            // cannot reference other lanes until pass or slice are not zero
            int refLane = position is { Pass: 0, Slice: 0 } ? 
                position.Lane : 
                (int)((uint)(pseudoRand >> 32) % (uint)m_config.Lanes);

            // compute possible number of reference blocks in lane
            position.Index = i;
            int refIndex = IndexAlpha(position, (uint)pseudoRand, refLane == position.Lane);

            BlockValues refBlock = Memory[LaneBlockCount * refLane + refIndex];
            BlockValues curBlock = Memory[curOffset];
            
            if (m_config.Version == Argon2Version.Sixteen)
                FillBlock(Memory[prevOffset], refBlock, curBlock); // version 1.2.1 and earlier: overwrite, not XOR
            else if (position.Pass == 0)
                FillBlock(Memory[prevOffset], refBlock, curBlock);
            else
                FillBlockWithXor(Memory[prevOffset], refBlock, curBlock);
        }
    }

    private int IndexAlpha(Position position, uint pseudoRand, bool sameLane)
    {
        // Pass 0:
        //   This lane : all already finished segments plus already constructed
        //   blocks in this segment
        // Other lanes : all already finished segments
        // Pass 1+:
        //   This lane : (SYNC_POINTS - 1) last segments plus already constructed
        //   blocks in this segment
        //   Other lanes : (SYNC_POINTS - 1) last segments
        int referenceAreaSize;

        if (position.Pass == 0)
        {
            // first pass
            if (position.Slice == 0)
            {
                // first slice
                referenceAreaSize = position.Index - 1; // all but previous
            }
            else
            {
                if (sameLane)
                    referenceAreaSize =
                        position.Slice * SegmentBlockCount + position.Index - 1; // same lane, add current segment
                else
                    referenceAreaSize = position.Slice * SegmentBlockCount + (position.Index == 0 ? -1 : 0);
            }
        }
        else
        {
            // second pass
            if (sameLane)
                referenceAreaSize = LaneBlockCount - SegmentBlockCount + position.Index - 1;
            else
                referenceAreaSize = LaneBlockCount - SegmentBlockCount + (position.Index == 0 ? -1 : 0);
        }

        ulong relativePosition = pseudoRand;
        relativePosition = (relativePosition * relativePosition) >> 32;
        relativePosition = (uint)referenceAreaSize - 1 - (((uint)referenceAreaSize * relativePosition) >> 32);

        int startPosition = position.Pass != 0 ? position.Slice == SyncPointCount - 1 ? 0 : (position.Slice + 1) * SegmentBlockCount : 0;
        int absolutePosition = (int)(((ulong)startPosition + relativePosition) % (ulong)LaneBlockCount);
        return absolutePosition;
    }

    private void GenerateAddresses(Position position, ulong[] pseudoRands)
    {
        ulong[] buf = new ulong[QwordsInBlock * 4];
        BlockValues zeroBlock = new(buf, 0);
        BlockValues inputBlock = new(buf, 1);
        BlockValues addressBlock = new(buf, 2);
        BlockValues tmpBlock = new(buf, 3);

        inputBlock[0] = (ulong)position.Pass;
        inputBlock[1] = (ulong)position.Lane;
        inputBlock[2] = (ulong)position.Slice;
        inputBlock[3] = (ulong)MemoryBlockCount;
        inputBlock[4] = (ulong)m_config.TimeCost;
        inputBlock[5] = (ulong)m_config.Type;
        
        for (int i = 0; i < SegmentBlockCount; ++i)
        {
            if (i % QwordsInBlock == 0)
            {
                inputBlock[6] += 1;

                tmpBlock.Init(0);
                addressBlock.Init(0);

                FillBlockWithXor(zeroBlock, inputBlock, tmpBlock);
                FillBlockWithXor(zeroBlock, tmpBlock, addressBlock);
            }

            pseudoRands[i] = addressBlock[i % QwordsInBlock];
        }
    }

    private sealed class Position
    {
        public int Pass { get; init; }

        public int Lane { get; init; }

        public int Slice { get; init; }

        public int Index { get; set; }
    }

    private sealed class FillState(Position position, AutoResetEvent are)
    {
        public Position Position { get; } = position;

        public AutoResetEvent Are { get; } = are;
    }
}
