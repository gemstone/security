// <copyright file="Argon2.Helpers.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Gemstone.Security.Cryptography.Argon2Hash;

/// <summary>
/// Argon2 Hashing of passwords.
/// </summary>
public sealed partial class Argon2
{
    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="configToHash">
    /// Contains all the information used to create the hash returned.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(Argon2Config configToHash)
    {
        using Argon2 argon2 = new(configToHash);
        using ZeroedBuffer<byte> hash = argon2.Hash();
        return argon2.m_config.EncodeString(hash.Buffer);
    }

    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="password">
    /// The password to hash. Gets UTF-8 encoded before hashing.
    /// </param>
    /// <param name="secret">
    /// The secret to use in creating the hash.
    /// </param>
    /// <param name="timeCost">
    /// The time cost to use. Defaults to 3.
    /// </param>
    /// <param name="memoryCost">
    /// The target memory cost to use. Defaults to 65536 (65536 * 1024 = 64MB). <see
    /// cref="Argon2Config.MemoryCost"/> for detail on calculating the actual memory
    /// used from this value.
    /// </param>
    /// <param name="parallelism">
    /// The parallelism to use. Default to 1 (single threaded).
    /// </param>
    /// <param name="type">
    /// Data-dependent, data-independent, or hybrid. Defaults to hybrid
    /// (as recommended for password hashing).
    /// </param>
    /// <param name="hashLength">
    /// The length of the hash in bytes. Note, the string returned base-64
    /// encodes this with other parameters so the resulting string is
    /// significantly longer.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(
        byte[] password,
        byte[]? secret,
        int timeCost = 3,
        int memoryCost = 65536,
        int parallelism = 1,
        Argon2Type type = Argon2Type.HybridAddressing,
        int hashLength = 32)
    {
        byte[] salt = new byte[16];

        GetSalt(salt);

        return Hash(new Argon2Config
        {
            TimeCost = timeCost,
            MemoryCost = memoryCost,
            Threads = parallelism,
            Lanes = parallelism,
            Password = password,
            Secret = secret,
            Salt = salt,
            HashLength = hashLength,
            Version = Argon2Version.Nineteen,
            Type = type
        });
    }

    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="password">
    /// The password to hash. Gets UTF-8 encoded before hashing.
    /// </param>
    /// <param name="secret">
    /// The secret to use in creating the hash. UTF-8 encoded before hashing. May be null. A
    /// <c>string.Empty</c> is treated the same as null.
    /// </param>
    /// <param name="timeCost">
    /// The time cost to use. Defaults to 3.
    /// </param>
    /// <param name="memoryCost">
    /// The target memory cost to use. Defaults to 65536 (65536 * 1024 = 64MB). <see
    /// cref="Argon2Config.MemoryCost"/> for detail on calculating the actual memory
    /// used from this value.
    /// </param>
    /// <param name="parallelism">
    /// The parallelism to use. Default to 1 (single threaded).
    /// </param>
    /// <param name="type">
    /// Data-dependent, data-independent, or hybrid. Defaults to hybrid
    /// (as recommended for password hashing).
    /// </param>
    /// <param name="hashLength">
    /// The length of the hash in bytes. Note, the string returned base-64
    /// encodes this with other parameters so the resulting string is
    /// significantly longer.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(
        string password,
        string? secret,
        int timeCost = 3,
        int memoryCost = 65536,
        int parallelism = 1,
        Argon2Type type = Argon2Type.HybridAddressing,
        int hashLength = 32)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));

        ZeroedBuffer<byte>? secretBuf = string.IsNullOrEmpty(secret) ? null : new ZeroedBuffer<byte>(Encoding.UTF8.GetByteCount(secret));

        try
        {
            if (secretBuf != null)
                Encoding.UTF8.GetBytes(secret!, 0, secret!.Length, secretBuf.Buffer, 0);

            using ZeroedBuffer<byte> passwordBuf = new(Encoding.UTF8.GetByteCount(password));
            
            Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
            
            return Hash(
                passwordBuf.Buffer,
                secretBuf?.Buffer,
                timeCost,
                memoryCost,
                parallelism,
                type,
                hashLength);
        }
        finally
        {
            secretBuf?.Dispose();
        }
    }

    /// <summary>
    /// Hash the given password to an Argon2 hash string.
    /// </summary>
    /// <param name="password">
    /// The password to hash. Gets UTF-8 encoded before hashing.
    /// </param>
    /// <param name="timeCost">
    /// The time cost to use. Defaults to 3.
    /// </param>
    /// <param name="memoryCost">
    /// The target memory cost to use. Defaults to 65536 (65536 * 1024 = 64MB). <see
    /// cref="Argon2Config.MemoryCost"/> for detail on calculating the actual memory
    /// used from this value.
    /// </param>
    /// <param name="parallelism">
    /// The parallelism to use. Defaults to 1 (single threaded).
    /// </param>
    /// <param name="type">
    /// Data-dependent, data-independent, or hybrid. Defaults to hybrid
    /// (as recommended for password hashing).
    /// </param>
    /// <param name="hashLength">
    /// The length of the hash in bytes. Note, the string returned base-64
    /// encodes this with other parameters so the resulting string is
    /// significantly longer.
    /// </param>
    /// <returns>
    /// The Argon2 hash of the given password.
    /// </returns>
    public static string Hash(
        string password,
        int timeCost = 3,
        int memoryCost = 65536,
        int parallelism = 1,
        Argon2Type type = Argon2Type.HybridAddressing,
        int hashLength = 32)
    {
        return Hash(password, null, timeCost, memoryCost, parallelism, type, hashLength);
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="configToVerify">
    /// The configuration that contains the values used to created <paramref name="encoded"/>.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        Argon2Config configToVerify)
    {
        ZeroedBuffer<byte>? hash = null;

        try
        {
            if (!configToVerify.DecodeString(encoded, out hash) || hash == null)
                return false;

            using Argon2 hasherToVerify = new(configToVerify);
            using ZeroedBuffer<byte> hashToVerify = hasherToVerify.Hash();

            return FixedTimeEquals(hash, hashToVerify);
        }
        finally
        {
            hash?.Dispose();
        }
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="secret">
    /// The secret hashed into the password.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        byte[]? secret)
    {
        Argon2Config configToVerify = new()
        {
            Password = password,
            Secret = secret
        };

        return Verify(encoded, configToVerify);
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="secret">
    /// The secret hashed into the password.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        byte[]? secret,
        int threads)
    {
        Argon2Config configToVerify = new()
        {
            Password = password,
            Secret = secret,
            Threads = threads
        };

        return Verify(encoded, configToVerify);
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password)
    {
        return Verify(encoded, password, null);
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        byte[] password,
        int threads)
    {
        return Verify(encoded, password, null, threads);
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="secret">
    /// The secret used in the creation of <paramref name="encoded"/>. UTF-8 encoded to create the byte-buffer actually used in the verification.
    /// May be null for no secret. <c>string.Empty</c> is treated as null.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        string? secret)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));

        ZeroedBuffer<byte>? secretBuf = string.IsNullOrEmpty(secret) ? null : new ZeroedBuffer<byte>(Encoding.UTF8.GetByteCount(secret));

        try
        {
            if (secretBuf != null)
                Encoding.UTF8.GetBytes(secret!, 0, secret!.Length, secretBuf.Buffer, 0);

            using ZeroedBuffer<byte> passwordBuf = new(Encoding.UTF8.GetByteCount(password));
            
            Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
            
            return Verify(encoded, passwordBuf.Buffer, secretBuf?.Buffer);
        }
        finally
        {
            secretBuf?.Dispose();
        }
    }

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="secret">
    /// The secret used in the creation of <paramref name="encoded"/>. UTF-8 encoded to create the byte-buffer actually used in the verification.
    /// May be null for no secret. <c>string.Empty</c> is treated as null.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        string? secret,
        int threads)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));

        ZeroedBuffer<byte>? secretBuf = string.IsNullOrEmpty(secret) ? null : new ZeroedBuffer<byte>(Encoding.UTF8.GetByteCount(secret));

        try
        {
            if (secretBuf != null) 
                Encoding.UTF8.GetBytes(secret!, 0, secret!.Length, secretBuf.Buffer, 0);

            using ZeroedBuffer<byte> passwordBuf = new(Encoding.UTF8.GetByteCount(password));
            
            Encoding.UTF8.GetBytes(password, 0, password.Length, passwordBuf.Buffer, 0);
            
            return Verify(encoded, passwordBuf.Buffer, secretBuf?.Buffer, threads);
        }
        finally
        {
            secretBuf?.Dispose();
        }
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password)
    {
        return Verify(encoded, password, null);
    }

    // ReSharper disable once UnusedMember.Global

    /// <summary>
    /// Verify the given Argon2 hash as being that of the given password.
    /// </summary>
    /// <param name="encoded">
    /// The Argon2 hash string. This has the actual hash along with other parameters used in the hash.
    /// </param>
    /// <param name="password">
    /// The password to verify. This gets UTF-8 encoded.
    /// </param>
    /// <param name="threads">
    /// The number of threads to use. Setting this to a higher number than
    /// the "p=" parameter in the <paramref name="encoded"/> string doesn't
    /// cause even more parallelism.
    /// </param>
    /// <returns>
    /// True on success; false otherwise.
    /// </returns>
    public static bool Verify(
        string encoded,
        string password,
        int threads)
    {
        return Verify(encoded, password, null, threads);
    }

    /// <summary>
    /// Compare two ZeroedBuffers without leaking timing information.
    /// </summary>
    /// <param name="left">The first ZeroedBuffer to compare.</param>
    /// <param name="right">The second ZeroedBuffer to compare.</param>
    /// <returns>true if left and right have the same values for Length and the same contents; otherwise, false.</returns>
    /// <remarks>
    /// Uses <see
    /// href="https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals"
    /// >System.Security.Cryptography.CryptographicOperations.FixedTimeEquals()</see>
    /// when available; otherwise implements a similar algorithm.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(ZeroedBuffer<byte> left, ZeroedBuffer<byte> right)
    {
        if (left == null)
            throw new ArgumentNullException(nameof(left));

        if (right == null)
            throw new ArgumentNullException(nameof(right));

        return CryptographicOperations.FixedTimeEquals(left.Buffer, right.Buffer);
    }

    private static void GetSalt(byte[] salt)
    {
        using RandomNumberGenerator? randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(salt);
    }
}
