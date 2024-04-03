// <copyright file="Blocks.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System.Collections.Generic;

namespace Gemstone.Security.Cryptography.Argon2Hash;

/// <summary>
/// Break a byte array into blocks for Argon2 to use.
/// </summary>
public class Blocks
{
    /// <summary>
    /// The array of blocks broken into <see cref="BlockValues"/>
    /// which actually return the values in the original array.
    /// </summary>
    private readonly BlockValues[] m_blockValues;

    /// <summary>
    /// Initializes a new instance of the <see cref="Blocks"/> class.
    /// </summary>
    /// <param name="memories">
    /// The arrays to use under the blocks.
    /// </param>
    public Blocks(IEnumerable<ulong[]> memories)
    {
        List<BlockValues> bvs = new();
        int blockIndex = 0;
        
        foreach (ulong[] memory in memories)
        {
            int maxBlockIndex = blockIndex + memory.Length / Argon2.QwordsInBlock;

            for (int i = blockIndex; i < maxBlockIndex; ++i) 
                bvs.Add(new BlockValues(memory, i - blockIndex));

            blockIndex = maxBlockIndex;
        }

        m_blockValues = bvs.ToArray();
    }

    /// <summary>
    /// Gets the total number of <see cref="BlockValues"/> in the <see cref="Blocks"/>.
    /// </summary>
    public int Length => m_blockValues.Length;

    /// <summary>
    /// Gets or sets the <see cref="BlockValues"/> element at the specified index.
    /// </summary>
    /// <param name="i">
    /// The <see cref="BlockValues"/> element to get or set.
    /// </param>
    /// <returns>
    /// The requested <see cref="BlockValues"/> element.
    /// </returns>
    public BlockValues this[int i] => m_blockValues[i];
}
