// <copyright file="Argon2.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using System.Collections.Generic;
using System.Linq;

namespace Gemstone.Security.Cryptography.Argon2Hash;

/// <summary>
/// Represents an Argon2 password hashing algorithm.
/// </summary>
public sealed partial class Argon2 : IDisposable
{
    private readonly List<ZeroedBuffer<ulong>> m_memories = new();
    private readonly Argon2Config m_config;

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2"/> class.
    /// </summary>
    /// <param name="config">
    /// The configuration to use.
    /// </param>
    public Argon2(Argon2Config config)
    {
        m_config = config ?? throw new ArgumentNullException(nameof(config), "Argon2 requires configuration information. Accepting the defaults except for the password is fine.");
        uint memoryBlocks = (uint)config.MemoryCost;
        
        if (memoryBlocks < 2 * SyncPointCount * config.Lanes)
            memoryBlocks = 2 * SyncPointCount * (uint)config.Lanes;

        SegmentBlockCount = (int)(memoryBlocks / (config.Lanes * SyncPointCount));

        // ensure that all segments have equal length
        LaneBlockCount = SegmentBlockCount * SyncPointCount;
        MemoryBlockCount = LaneBlockCount * config.Lanes;
        ulong memoryBlockCount = (ulong)MemoryBlockCount;

        try
        {
            while (memoryBlockCount > CsharpMaxBlocksPerArray)
            {
                m_memories.Add(new ZeroedBuffer<ulong>(QwordsInBlock * CsharpMaxBlocksPerArray));
                memoryBlockCount -= CsharpMaxBlocksPerArray;
            }

            m_memories.Add(new ZeroedBuffer<ulong>(QwordsInBlock * (int)memoryBlockCount));
        }
        catch (OutOfMemoryException ex)
        {
            int memoryCount = m_memories.Count;

            // be nice, clear allocated memory that will never be used sooner rather than later
            m_memories.ForEach(m => m?.Dispose());
            m_memories.Clear();
            
            throw new OutOfMemoryException(
                $"Failed to allocate {(memoryBlockCount > CsharpMaxBlocksPerArray ? CsharpMaxBlocksPerArray : memoryBlockCount) * QwordsInBlock}-byte Argon2 block array, " +
                $"{(memoryCount > 0 ? $" allocation {memoryCount + 1} of multiple-allocation," : string.Empty)}" +
                $" memory cost {config.MemoryCost}, lane count {config.Lanes}.",
                ex);
        }
        catch (Exception)
        {
            // be nice, clear allocated memory that will never be used sooner rather than later
            m_memories.ForEach(m => m?.Dispose());
            m_memories.Clear();
            throw;
        }

        Memory = new Blocks(m_memories.Select(m => m.Buffer));
        
        //// Console.WriteLine($"Memory Cost {config.MemoryCost}, Chunks {this.memories.Count}, Lanes {config.Lanes}, Memory {memoryBlockCount * 1024}, Block count {this.Memory.Length}, MemoryBlockCount {this.MemoryBlockCount}");
    }

    /// <summary>
    /// Gets the <see cref="MemoryBlockCount"/> blocks.
    /// </summary>
    public Blocks Memory { get; }

    /// <summary>
    /// Gets the number of memory blocks, (<see cref="Argon2Config.Lanes"/>*<see cref="LaneBlockCount"/>).
    /// </summary>
    public int MemoryBlockCount { get; }

    /// <summary>
    /// Gets the number of memory blocks per segment. This value gets
    /// derived from the memory cost. The memory cost value is a request
    /// for that number of blocks. If that request is less than (2 *
    /// <see cref="SyncPointCount"/>) times the number of lanes requested,
    /// it is first bumped up to that amount. Then, it may be reduced to
    /// fit on a <see cref="SyncPointCount"/> times the number of lanes
    /// requested boundary.
    /// </summary>
    public int SegmentBlockCount { get; }

    /// <summary>
    /// Gets the number of memory blocks per lane. <see cref="SegmentBlockCount"/> * <see cref="SyncPointCount"/>.
    /// </summary>
    public int LaneBlockCount { get; }

    /// <summary>
    /// Perform the hash.
    /// </summary>
    /// <returns>
    /// The hash bytes.
    /// </returns>
    public ZeroedBuffer<byte> Hash()
    {
        Initialize();
        FillMemoryBlocks();
        return Final();
    }

    /// <summary>
    /// Zero sensitive memories and dispose of resources.
    /// </summary>
    public void Dispose()
    {
        m_memories.ForEach(m => m?.Dispose());
        m_memories.Clear();
    }
}
