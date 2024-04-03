﻿// <copyright file="Argon2.Blake2BLong.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using Gemstone.Security.Cryptography.Blake2BHash;

namespace Gemstone.Security.Cryptography.Argon2Hash;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    /// <summary>
    /// Does a Blake2 hash with the ability to truncate or extend the hash to any length.
    /// </summary>
    /// <param name="hash">
    /// The buffer to fill with the hash.
    /// </param>
    /// <param name="inputBuffer">
    /// What to hash.
    /// </param>
    private static void Blake2BLong(byte[] hash, byte[] inputBuffer)
    {
        byte[] outputLengthBytes = new byte[4];
        
        using ZeroedBuffer<byte> intermediateHash = new(Blake2B.OutputLength);

        Blake2BConfig blake2BConfig = new()
        {
            Result64ByteBuffer = intermediateHash.Buffer,
            OutputSizeInBytes = hash.Length > 64 ? 64 : hash.Length,
        };

        Store32(outputLengthBytes, hash.Length);

        using (Hasher blakeHash = Blake2B.Create(blake2BConfig))
        {
            blakeHash.Update(outputLengthBytes);
            blakeHash.Update(inputBuffer);
            blakeHash.Finish();
        }

        if (hash.Length <= intermediateHash.Buffer.Length)
        {
            // less than or equal to 64 bytes, just copy the hash result
            Array.Copy(intermediateHash.Buffer, hash, hash.Length);
            return;
        }

        // greater than 64 bytes, copy a chain of half-hash results until the final up-to-full hash result
        const int b2B2 = Blake2B.OutputLength / 2;
        Array.Copy(intermediateHash.Buffer, hash, b2B2); // copy half hash result

        int pos = b2B2;
        int lastHashIndex = hash.Length - Blake2B.OutputLength;
        using ZeroedBuffer<byte> toHash = new(Blake2B.OutputLength);
        
        while (pos < lastHashIndex)
        {
            Array.Copy(intermediateHash.Buffer, toHash.Buffer, intermediateHash.Buffer.Length); // set toHash to be the previous hash
            Blake2B.ComputeHash(toHash.Buffer, blake2BConfig);
            Array.Copy(intermediateHash.Buffer, 0, hash, pos, b2B2); // copy half hash result
            pos += b2B2;
        }

        // between 33 and 64 bytes left to load
        Array.Copy(intermediateHash.Buffer, toHash.Buffer, intermediateHash.Buffer.Length); // set toHash to be the previous hash
        
        int remaining = hash.Length - pos;
        
        if (remaining < 64)
        {
            blake2BConfig = new Blake2BConfig
            {
                Result64ByteBuffer = intermediateHash.Buffer,
                OutputSizeInBytes = hash.Length - pos,
            };
        }

        Blake2B.ComputeHash(toHash.Buffer, blake2BConfig);
        Array.Copy(intermediateHash.Buffer, 0, hash, pos, hash.Length - pos); // copy the final bytes from the first part of the hash result
    }
}
