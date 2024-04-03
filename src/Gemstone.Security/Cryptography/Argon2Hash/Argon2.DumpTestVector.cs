// <copyright file="Argon2.DumpTestVector.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using System.IO;

namespace Gemstone.Security.Cryptography.Argon2;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    // ReSharper disable once HeuristicUnreachableCode
    private static readonly string s_vectorFileName = true ? string.Empty : "argon2-test-vectors.txt";

    private static void InitialKat(byte[] buffer, Argon2 hasher)
    {
        if (s_vectorFileName.Length != 0)
        {
            using FileStream fileOut = new(s_vectorFileName, FileMode.Append);
            using StreamWriter streamOut = new(fileOut);
            streamOut.WriteLine("=======================================");
            switch (hasher.m_config.Type)
            {
                case Argon2Type.DataDependentAddressing:
                    streamOut.WriteLine($"Argon2d version number {(int)hasher.m_config.Version}");
                    break;
                case Argon2Type.DataIndependentAddressing:
                    streamOut.WriteLine($"Argon2i version number {(int)hasher.m_config.Version}");
                    break;
                case Argon2Type.HybridAddressing:
                    streamOut.WriteLine($"Argon2id version number {(int)hasher.m_config.Version}");
                    break;
            }

            streamOut.WriteLine("=======================================");
            streamOut.WriteLine(
                $"Memory: {hasher.m_config.MemoryCost} KiB, Iterations: {hasher.m_config.TimeCost}, "
                + $"Parallelism: {hasher.m_config.Lanes} lanes, Tag length: " + $"{hasher.m_config.HashLength} bytes");
            string pwText = hasher.m_config.ClearPassword
                ? "CLEARED"
                : BitConverter.ToString(hasher.m_config.Password ?? Array.Empty<byte>()).ToLowerInvariant().Replace('-', ' ');
            streamOut.WriteLine($"Password[{hasher.m_config.Password?.Length ?? -1}]: {pwText} ");
            streamOut.WriteLine(
                $"Salt[{hasher.m_config.Salt?.Length ?? 0}]: "
                + $"{(hasher.m_config.Salt == null ? string.Empty : BitConverter.ToString(hasher.m_config.Salt).ToLowerInvariant().Replace('-', ' '))} ");
            streamOut.WriteLine(
                $"Secret[{hasher.m_config.Secret?.Length ?? 0}]: "
                + $"{(hasher.m_config.Secret == null ? string.Empty : BitConverter.ToString(hasher.m_config.Secret).ToLowerInvariant().Replace('-', ' '))} ");
            streamOut.WriteLine(
                $"Associated data[{hasher.m_config.AssociatedData?.Length ?? 0}]: "
                + $"{(hasher.m_config.AssociatedData == null ? string.Empty : BitConverter.ToString(hasher.m_config.AssociatedData).ToLowerInvariant().Replace('-', ' '))} ");
            streamOut.WriteLine(
                $"Pre-hashing digest: {BitConverter.ToString(buffer, 0, PrehashDigestLength).ToLowerInvariant().Replace('-', ' ')} ");
        }
    }

    private static void InternalKat(Argon2 hasher, int passNumber)
    {
        if (s_vectorFileName.Length != 0)
        {
            using FileStream fileOut = new(s_vectorFileName, FileMode.Append);
            using StreamWriter streamOut = new(fileOut);
            streamOut.WriteLine();
            streamOut.WriteLine($" After pass {passNumber}:");
            for (int i = 0; i < hasher.MemoryBlockCount; ++i)
            {
                int howManyWords = hasher.MemoryBlockCount > QwordsInBlock ? 1 : QwordsInBlock;

                for (int j = 0; j < howManyWords; ++j)
                {
                    streamOut.WriteLine($"Block {i:D4} [{j,3}]: {hasher.Memory[i][j]:x16}");
                }
            }
        }
    }

    private static void PrintTag(byte[] output)
    {
        if (s_vectorFileName.Length != 0)
        {
            using FileStream fileOut = new(s_vectorFileName, FileMode.Append);
            using StreamWriter streamOut = new(fileOut);
            streamOut.WriteLine($"Tag: {BitConverter.ToString(output).ToLowerInvariant().Replace('-', ' ')} ");
        }
    }
}
