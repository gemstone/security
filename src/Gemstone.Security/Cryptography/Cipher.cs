﻿//******************************************************************************************************
//  Cipher.cs - Gbtc
//
//  Copyright © 2012, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the MIT License (MIT), the "License"; you may
//  not use this file except in compliance with the License. You may obtain a copy of the License at:
//
//      http://www.opensource.org/licenses/MIT
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  11/12/2003 - J. Ritchie Carroll
//       Generated original version of source code.
//  01/04/2006 - J. Ritchie Carroll
//       Migrated 2.0 version of source code from 1.1 source (GSF.Shared.Crypto).
//  02/28/2007 - J. Ritchie Carroll
//       Changed string-based encrypt and decrypt functions to return null if
//       input string to be encrypted or decrypted was null or empty.
//  10/11/2007 - J. Ritchie Carroll
//       Added Obfuscate and De-obfuscate functions that perform data obfuscation
//       based upon simple bit-rotation algorithms.
//  12/13/2007 - Darrell Zuercher
//       Edited code comments.
//  09/19/2008 - J. Ritchie Carroll
//       Converted to C# - basic encryption/decryption extends string, byte[], and Stream.
//  08/10/2009 - Josh L. Patterson
//       Edited Comments.
//  09/14/2009 - Stephen C. Wills
//       Added new header and license agreement.
//  10/05/2009 - J. Ritchie Carroll
//       Switched to AES only encryption/decryption using machine specific local key cache.
//  07/13/2010 - Stephen C. Wills
//       Added a file watcher to reload the KeyIV table when an external
//       process modifies the cache file.
//  03/17/2011 - J. Ritchie Carroll
//       Modified key and initialization vector cache to be able to operate in a non-elevated mode.
//  04/06/2011 - J. Ritchie Carroll
//       Added FlushCache() method to wait for pending key/IV cache serializations for applications
//       with a short life-cycle.
//  04/14/2011 - Pinal C. Patel
//       Updated to use new serialization and deserialization methods in GSF.Serialization class.
//  06/10/2011 - Pinal C. Patel
//       Renamed RetryDelayInterval and MaximumRetryAttempts settings persisted to the config file 
//       to CacheRetryDelayInterval and CacheMaximumRetryAttempts for clarity.
//  06/30/2011 - Stephen C. Wills - applying changes from Jian (Ryan) Zuo
//       Added ManagedEncryption setting to the config file to allow the user to switch to
//       wrappers over FIPS-compliant algorithms.
//  07/05/2011 - Stephen C. Wills
//       Removed config file setting for FIPS compliance. Checks the registry instead.
//  07/13/2011 - Stephen C. Wills
//       Modified check for FIPS compliance to work with Windows XP and Windows Server 2003.
//  02/17/2012 - Stephen C. Wills
//       Added public method to manually reload the key cache.
//  12/14/2012 - Starlynn Danyelle Gilliam
//       Modified Header.
//
//******************************************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Gemstone.ArrayExtensions;
using Gemstone.Collections.CollectionExtensions;
using Gemstone.Configuration;
using Gemstone.IO;
using Gemstone.IO.StreamExtensions;
using Gemstone.Security.Cryptography.Argon2Hash;
using Gemstone.Security.Cryptography.SymmetricAlgorithmExtensions;
using Microsoft.Win32;

namespace Gemstone.Security.Cryptography;

#region [ Enumerations ]

/// <summary>
/// Cryptographic strength enumeration.
/// </summary>
public enum CipherStrength
{
    /// <summary>Uses no encryption.</summary>
    None = 0,
    /// <summary>Uses AES 128-bit encryption.</summary>
    Aes128 = 128,
    /// <summary>Uses AES 256-bit encryption.</summary>
    Aes256 = 256
}

#endregion

/// <summary>
/// Provides general use cryptographic functions.
/// </summary>
/// <remarks>
/// This class exists to simplify usage of basic cryptography functionality.
/// </remarks>
public static class Cipher
{
    // Constants
    private const int KeyIndex = 0;
    private const int IVIndex = 1;

    // Default key and initialization vector cache file name
    private const string DefaultCacheFileName = "KeyIVCache.bin";

    // Default maximum retry attempts allowed for loading cryptographic key and initialization vector cache
    private const int DefaultMaximumRetryAttempts = 5;

    // Default wait interval, in milliseconds, before retrying load of cryptographic key and initialization vector cache
    private const double DefaultRetryDelayInterval = 1000.0D;

    // The standard settings category for cryptography information
    private const string CryptoServicesSettingsCategory = DataProtection.DefaultSettingsCategory;

    // Default Argon2 hash prefix
    private const string Argon2HashPrefix = "$argon2id$v=19$m=65536,t=3,p=1$";

    /// <summary>
    /// Represents an inter-process serializable cryptographic key and initialization vector cache.
    /// </summary>
    private class KeyIVCache : InterprocessCache
    {
        #region [ Members ]

        // Internal key and initialization vector table
        private Dictionary<string, byte[][]> m_keyIVTable = new();
        private readonly Lock m_keyIVTableLock = new();

        #endregion

        #region [ Properties ]

        /// <summary>
        /// Gets a copy of the internal key and initialization vector table.
        /// </summary>
        private Dictionary<string, byte[][]> KeyIVTable
        {
            get
            {
                Dictionary<string, byte[][]> keyIVTable;

                // We wait until the key and IV cache is loaded before attempting to access it
                WaitForDataReady();

                // Wait for thread level lock on key table
                lock (m_keyIVTableLock)
                {
                    // Make a copy of the keyIV table for external use
                    keyIVTable = new Dictionary<string, byte[][]>(m_keyIVTable);
                }

                return keyIVTable;
            }
        }

        #endregion

        #region [ Methods ]

        /// <summary>
        /// Gets the crypto key and initialization vector for the given user password.
        /// </summary>
        /// <param name="password">User password used for key lookup.</param>
        /// <param name="keySize">Specifies the desired key size.</param>
        /// <returns>Crypto key, index 0, and initialization vector, index 1, for the given user password.</returns>
        public byte[][] GetCryptoKeyIV(string password, int keySize)
        {
            string hash = GetPasswordHash(password, keySize);
            byte[][]? keyIV;
            bool addedKey = false;

            // We wait until the key and IV cache is loaded before attempting to access it
            WaitForDataReady();

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {
                // Lookup crypto key based on password hash in persisted key table
                if (!m_keyIVTable.TryGetValue(hash, out keyIV))
                {
                    // Key for password hash doesn't exist, create a new one
                    Aes symmetricAlgorithm = Aes.Create();

                    symmetricAlgorithm.KeySize = keySize;
                    symmetricAlgorithm.GenerateKey();
                    symmetricAlgorithm.GenerateIV();

                    byte[] key = symmetricAlgorithm.Key;
                    byte[] iv = symmetricAlgorithm.IV;
                    keyIV = [key, iv];

                    // Add new crypto key to key table
                    m_keyIVTable.Add(hash, keyIV);
                    addedKey = true;
                }
            }

            // Queue up a serialization for any newly added key
            if (addedKey)
                Save();

            return keyIV;
        }

        /// <summary>
        /// Determines if a key and initialization vector exists for the given <paramref name="password"/>.
        /// </summary>
        /// <param name="password">User password used for key lookups.</param>
        /// <param name="keySize">Specifies the desired key size.</param>
        /// <returns><c>true</c> if a key and initialization vector exists for the given <paramref name="password"/>; otherwise <c>false</c>.</returns>
        // ReSharper disable once MemberHidesStaticFromOuterClass
        public bool KeyIVExists(string password, int keySize)
        {
            string hash = GetPasswordHash(password, keySize);

            // We wait until the key and IV cache is loaded before attempting to access it
            WaitForDataReady();

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {
                // Lookup crypto key based on password hash in persisted key table
                return m_keyIVTable.ContainsKey(hash);
            }
        }

        /// <summary>
        /// Imports a key and initialization vector into the local system key cache.
        /// </summary>
        /// <param name="password">User password used for key lookups.</param>
        /// <param name="keySize">Specifies the desired key size.</param>
        /// <param name="keyIVText">Text based key and initialization vector to import into local key cache.</param>
        /// <remarks>
        /// This method is used to manually import a key created on another computer.
        /// </remarks>
        // ReSharper disable once MemberHidesStaticFromOuterClass
        public void ImportKeyIV(string password, int keySize, string keyIVText)
        {
            string hash = GetPasswordHash(password, keySize);

            // We wait until the key and IV cache is loaded before attempting to access it
            WaitForDataReady();

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {
                string[] keyIV = keyIVText.Split('|');
                byte[] key = Convert.FromBase64String(keyIV[KeyIndex]);
                byte[] iv = Convert.FromBase64String(keyIV[IVIndex]);

                // Assign new crypto key to key table
                m_keyIVTable[hash] = [key, iv];
            }

            // Queue up a serialization for this new key
            Save();
        }

        /// <summary>
        /// Exports a key and initialization vector from the local system key cache.
        /// </summary>
        /// <param name="password">User password used for key lookup.</param>
        /// <param name="keySize">Specifies the desired key size.</param>
        /// <returns>Text based key and initialization vector exported from local key cache.</returns>
        /// <remarks>
        /// This method is used to manually export a key to be installed on another computer. 
        /// </remarks>
        // ReSharper disable once MemberHidesStaticFromOuterClass
        public string ExportKeyIV(string password, int keySize)
        {
            byte[][] keyIV = GetCryptoKeyIV(password, keySize);
            return string.Concat(Convert.ToBase64String(keyIV[KeyIndex]), "|", Convert.ToBase64String(keyIV[IVIndex]));
        }

        /// <summary>
        /// Merge keys and initialization vectors from another <see cref="KeyIVCache"/>, local cache taking precedence.
        /// </summary>
        /// <param name="other">Other <see cref="KeyIVCache"/> to merge with.</param>
        public void MergeLeft(KeyIVCache other)
        {
            // Merge other keys into local ones
            Dictionary<string, byte[][]> mergedKeyIVTable = KeyIVTable.Merge(other.KeyIVTable);

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {
                // Replace local key IV table with merged items
                m_keyIVTable = mergedKeyIVTable;
            }

            // Queue up a serialization for any newly added keys
            Save();
        }

        /// <summary>
        /// Merge keys and initialization vectors from another <see cref="KeyIVCache"/>, other cache taking precedence.
        /// </summary>
        /// <param name="other">Other <see cref="KeyIVCache"/> to merge with.</param>
        public void MergeRight(KeyIVCache other)
        {
            // Merge other keys into local ones
            Dictionary<string, byte[][]> mergedKeyIVTable = other.KeyIVTable.Merge(KeyIVTable);

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {
                // Replace local key IV table with merged items
                m_keyIVTable = mergedKeyIVTable;
            }

            // Queue up a serialization for any newly added keys
            Save();
        }

        /// <summary>
        /// Initiates inter-process synchronized save of key and initialization vector table.
        /// </summary>
        public override void Save()
        {
            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream);

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {

                writer.Write(m_keyIVTable.Count);

                foreach (KeyValuePair<string, byte[][]> keyIV in m_keyIVTable)
                {
                    writer.Write(keyIV.Key);
                    writer.Write(keyIV.Value[KeyIndex].Length);
                    writer.Write(keyIV.Value[KeyIndex]);
                    writer.Write(keyIV.Value[IVIndex].Length);
                    writer.Write(keyIV.Value[IVIndex]);
                }
            }

            // File data is the serialized Key/IV cache, assignment will initiate auto-save if needed
            FileData = stream.ToArray();
        }

        /// <summary>
        /// Handles serialization of file to disk; virtual method allows customization (e.g., pre-save encryption and/or data merge).
        /// </summary>
        /// <param name="fileStream"><see cref="FileStream"/> used to serialize data.</param>
        /// <param name="fileData">File data to be serialized.</param>
        /// <remarks>
        /// Consumers overriding this method should not directly call <see cref="InterprocessCache.FileData"/> property to avoid potential deadlocks.
        /// </remarks>
        protected override void SaveFileData(FileStream fileStream, byte[] fileData)
        {
            // Encrypt data local to this machine (this way user cannot copy key cache to another machine)
            base.SaveFileData(fileStream, DataProtection.Protect(fileData));
        }

        /// <summary>
        /// Handles deserialization of file from disk; virtual method allows customization (e.g., preload decryption and/or data merge).
        /// </summary>
        /// <param name="fileStream"><see cref="FileStream"/> used to deserialize data.</param>
        /// <returns>Deserialized file data.</returns>
        /// <remarks>
        /// Consumers overriding this method should not directly call <see cref="InterprocessCache.FileData"/> property to avoid potential deadlocks.
        /// </remarks>
        protected override byte[] LoadFileData(FileStream fileStream)
        {
            // Decrypt data that was encrypted local to this machine
            byte[] serializedKeyIVTable = DataProtection.Unprotect(fileStream.ReadStream());
            Dictionary<string, byte[][]> keyIVTable = new();

            using MemoryStream stream = new(serializedKeyIVTable);
            using BinaryReader reader = new(stream);

            int count = reader.ReadInt32();

            for (int i = 0; i < count; i++)
            {
                string key = reader.ReadString();
                byte[] keyData = reader.ReadBytes(reader.ReadInt32());
                byte[] ivData = reader.ReadBytes(reader.ReadInt32());

                keyIVTable.Add(key, [keyData, ivData]);
            }

            // Wait for thread level lock on key table
            lock (m_keyIVTableLock)
            {
                // Merge new and existing key tables since new keys may have been queued for serialization, but not saved yet
                m_keyIVTable = keyIVTable.Merge(m_keyIVTable);
            }

            return serializedKeyIVTable;
        }

        // Waits until the key and IV cache is loaded before attempting to access it
        private void WaitForDataReady()
        {
            try
            {
                // Just wrapping this method to provide a more detailed exception message if there is an issue loading cache
                WaitForLoad();
            }
            catch (Exception ex)
            {
                throw new UnauthorizedAccessException("Cryptographic cipher failure: timeout while attempting to load cryptographic key cache.", ex);
            }
        }

        #endregion
    }

    // Primary cryptographic key and initialization vector cache.
    private static KeyIVCache GlobalKeyIVCache => s_keyIVCache.Value;
    private static readonly Lazy<KeyIVCache> s_keyIVCache;

    /// <summary>
    /// Gets a flag that determines if system will allow use of managed, i.e., non-FIPS compliant, security algorithms.
    /// </summary>
    public static bool SystemAllowsManagedEncryption { get; }

    static Cipher()
    {
        if (Common.IsPosixEnvironment)
        {
            SystemAllowsManagedEncryption = true;
        }
        else
        {
            const string FipsKeyOld = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa";
            const string FipsKeyNew = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy";

            // Determine if the user needs to use FIPS-compliant algorithms
            try
            {
            #pragma warning disable CA1416
                SystemAllowsManagedEncryption =
                    (Registry.GetValue(FipsKeyNew, "Enabled", 0) ??
                     Registry.GetValue(FipsKeyOld, "FIPSAlgorithmPolicy", 0))?.ToString() == "0";
            #pragma warning restore CA1416
            }
            catch (Exception ex)
            {
                SystemAllowsManagedEncryption = true;
                LibraryEvents.OnSuppressedException(typeof(Cipher), new Exception($"Cipher FIPS compliance lookup exception: {ex.Message}", ex));
            }
        }

        KeyIVCache? localKeyIVCache;

        // Load cryptographic settings
        dynamic section = Settings.Default[CryptoServicesSettingsCategory];

        string localCacheFileName = FilePath.GetAbsolutePath(section["CryptoCache", DefaultCacheFileName, "Path and file name of cryptographic key and initialization vector cache."]);
        double retryDelayInterval = section["CacheRetryDelayInterval", DefaultRetryDelayInterval, "Wait interval, in milliseconds, before retrying load of cryptographic key and initialization vector cache."];
        int maximumRetryAttempts = section["CacheMaximumRetryAttempts", DefaultMaximumRetryAttempts, "Maximum retry attempts allowed for loading cryptographic key and initialization vector cache."];

        s_keyIVCache = new Lazy<KeyIVCache>(() =>
        {
            KeyIVCache globalKeyIVCache;

            // Initialize local cryptographic key and initialization vector cache (application may only have read-only access to this cache)
            localKeyIVCache = new KeyIVCache
            {
                FileName = localCacheFileName,
                RetryDelayInterval = retryDelayInterval,
                MaximumRetryAttempts = maximumRetryAttempts,
                ReloadOnChange = true,
                AutoSave = false
            };

            // Load initial keys
            localKeyIVCache.Load();

            try
            {
                // Validate that user has write access to the local cryptographic cache folder
                string tempFile = FilePath.GetDirectoryName(localCacheFileName) + Guid.NewGuid() + ".tmp";

                using (File.Create(tempFile))
                {
                }

                if (File.Exists(tempFile))
                    File.Delete(tempFile);

                // No access issues exist, use local cache as the primary cryptographic key and initialization vector cache
                globalKeyIVCache = localKeyIVCache;
                globalKeyIVCache.AutoSave = true;
                localKeyIVCache = null;
            }
            catch (UnauthorizedAccessException)
            {
                // User does not have needed serialization access to common cryptographic cache folder, use a path where user will have rights
                string userCacheFolder = FilePath.AddPathSuffix(FilePath.GetApplicationDataFolder());
                string userCacheFileName = userCacheFolder + FilePath.GetFileName(localCacheFileName);

                // Make sure user directory exists
                if (!Directory.Exists(userCacheFolder))
                    Directory.CreateDirectory(userCacheFolder);

                // Copy existing common cryptographic cache if none exists
                if (File.Exists(localCacheFileName) && !File.Exists(userCacheFileName))
                    File.Copy(localCacheFileName, userCacheFileName);

                // Initialize primary cryptographic key and initialization vector cache within user folder
                globalKeyIVCache = new KeyIVCache
                {
                    FileName = userCacheFileName,
                    RetryDelayInterval = retryDelayInterval,
                    MaximumRetryAttempts = maximumRetryAttempts,
                    ReloadOnChange = true,
                    AutoSave = true
                };

                // Load initial keys
                globalKeyIVCache.Load();

                // Merge new or updated keys, protected folder keys taking precedence over user keys
                globalKeyIVCache.MergeRight(localKeyIVCache!);
            }

            localKeyIVCache?.Dispose();

            return globalKeyIVCache;
        });
    }

    /// <summary>
    /// Blocks current thread and waits for any pending save of local system key cache to complete.
    /// </summary>
    /// <param name="millisecondsTimeout">The number of milliseconds to wait, or <see cref="Timeout.Infinite"/>(-1) to wait indefinitely.</param>
    /// <remarks>
    /// <para>
    /// This method only needs to be used if crypto cache changes could be pending during application shutdown (i.e., executing ciphers with
    /// new keys that have not been saved, using existing keys does not queue crypto cache updates) to ensure keys are flushed before exit.
    /// </para>
    /// <para>
    /// For most applications it is expected that this method would rarely be needed. However, possible usage scenarios would include:<br/>
    /// <list type="bullet">
    ///   <item>
    ///     <description>
    ///     Writing an application that establishes crypto keys where application lifetime would be very short (i.e., run, create keys, exit).
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///     Creating new crypto keys during application shutdown (i.e., performing ciphers with non-existing keys at shutdown).
    ///     </description>
    ///   </item>
    /// </list>
    /// </para>
    /// </remarks>
    public static void FlushCache(int millisecondsTimeout = Timeout.Infinite)
    {
        GlobalKeyIVCache.WaitForSave(millisecondsTimeout);
    }

    /// <summary>
    /// Manually loads keys into the local system key cache.
    /// </summary>
    public static void ReloadCache()
    {
        // Load the system key cache
        GlobalKeyIVCache.Load();

        // Load cryptographic settings
        dynamic section = Settings.Default[CryptoServicesSettingsCategory];
        string commonCacheFileName = FilePath.GetAbsolutePath(section.CryptoCache ?? DefaultCacheFileName);

        if (commonCacheFileName == GlobalKeyIVCache.FileName)
            return;

        // System key cache is not loaded from common cache folder.
        // We need to merge the common key cache with the system key cache.
        double retryDelayInterval = section.CacheRetryDelayInterval ?? DefaultRetryDelayInterval;
        int maximumRetryAttempts = section.CacheMaximumRetryAttempts ?? DefaultMaximumRetryAttempts;

        // Initialize local cryptographic key and initialization vector cache (application may only have read-only access to this cache)
        using KeyIVCache commonKeyIVCache = new() { FileName = commonCacheFileName };
        
        commonKeyIVCache.RetryDelayInterval = retryDelayInterval;
        commonKeyIVCache.MaximumRetryAttempts = maximumRetryAttempts;
        commonKeyIVCache.ReloadOnChange = false;
        commonKeyIVCache.AutoSave = false;

        // Load initial keys
        commonKeyIVCache.Load();

        // Merge new or updated keys, common cache folder keys taking precedence
        GlobalKeyIVCache.MergeRight(commonKeyIVCache);
    }

    /// <summary>
    /// Determines if a key and initialization vector exists for the given <paramref name="password"/> in the local system key cache.
    /// </summary>
    /// <param name="password">User password used for key lookups.</param>
    /// <param name="keySize">Specifies the desired key size.</param>
    /// <returns><c>true</c> if a key and initialization vector exists for the given <paramref name="password"/>; otherwise <c>false</c>.</returns>
    public static bool KeyIVExists(string password, int keySize)
    {
        return GlobalKeyIVCache.KeyIVExists(password, keySize);
    }

    /// <summary>
    /// Imports a key and initialization vector into the local system key cache.
    /// </summary>
    /// <param name="password">User password used for key lookups.</param>
    /// <param name="keySize">Specifies the desired key size.</param>
    /// <param name="keyIVText">Text based key and initialization vector to import into local key cache.</param>
    /// <remarks>
    /// This method is used to manually import a key created on another computer.
    /// </remarks>
    public static void ImportKeyIV(string password, int keySize, string keyIVText)
    {
        GlobalKeyIVCache.ImportKeyIV(password, keySize, keyIVText);
    }

    /// <summary>
    /// Exports a key and initialization vector from the local system key cache.
    /// </summary>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="keySize">Specifies the desired key size.</param>
    /// <returns>Text based key and initialization vector exported from local key cache.</returns>
    /// <remarks>
    /// This method is used to manually export a key to be installed on another computer. 
    /// </remarks>
    public static string ExportKeyIV(string password, int keySize)
    {
        return GlobalKeyIVCache.ExportKeyIV(password, keySize);
    }

    /// <summary>
    /// Gets the Base64 encoded SHA-256 hash of given user password.
    /// </summary>
    /// <param name="password">User password to get hash for.</param>
    /// <param name="categoryID">Specifies the optional category ID.</param>
    /// <returns>Base64 encoded SHA-256 hash of user password.</returns>
    /// <remarks>
    /// The optional <paramref name="categoryID"/> will be appended to the <paramref name="password"/> to allow
    /// the same password to be used in different contexts and return different results, when useful.
    /// </remarks>
    public static string GetPasswordHash(string password, int categoryID = 0)
    {
        // Suffix password with category ID (e.g., key size) since same password may be in use for different category IDs
        password += categoryID.ToString();

        string hash = Argon2.Hash(password);
        
        // Remove common Argon2 hash prefix
        return hash.StartsWith(Argon2HashPrefix) ? hash[Argon2HashPrefix.Length..] : hash;
    }

    /// <summary>
    /// Verifies the given user password against a given hash.
    /// </summary>
    /// <param name="hash">Stored hash.</param>
    /// <param name="password">User provide password.</param>
    /// <param name="categoryID">Specifies the optional category ID.</param>
    /// <returns>
    /// <c>true</c> if the given user password matches the stored hash; otherwise, <c>false</c>.
    /// </returns>
    public static bool VerifyPasswordHash(string hash, string password, int categoryID = 0)
    {
        // Suffix password with category ID (e.g., key size) since same password may be in use for different category IDs
        password += categoryID.ToString();

        // Re-add common Argon2 hash prefix if missing
        if (!hash.StartsWith("$argon2"))
            hash = Argon2HashPrefix + hash;

        return Argon2.Verify(hash, password);
    }

    /// <summary>
    /// Returns a Base64 encoded string of the returned binary array of the encrypted data, generated with
    /// the given parameters.
    /// </summary>
    /// <param name="source">Source string to encrypt.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting string.</param>
    /// <returns>An encrypted version of the source string.</returns>
    public static string Encrypt(this string source, string password, CipherStrength strength)
    {
        return strength == CipherStrength.None ? source : Convert.ToBase64String(Encoding.UTF8.GetBytes(source).Encrypt(password, strength));
    }

    /// <summary>
    /// Returns a binary array of encrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to encrypt.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting data.</param>
    /// <returns>An encrypted version of the source data.</returns>
    public static byte[] Encrypt(this byte[] source, string password, CipherStrength strength)
    {
        return source.Encrypt(0, source.Length, password, strength);
    }

    /// <summary>
    /// Returns a binary array of encrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to encrypt.</param>
    /// <param name="startIndex">Offset into <paramref name="source"/> buffer.</param>
    /// <param name="length">Number of bytes in <paramref name="source"/> buffer to encrypt starting from <paramref name="startIndex"/> offset.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting data.</param>
    /// <returns>An encrypted version of the source data.</returns>
    public static byte[] Encrypt(this byte[] source, int startIndex, int length, string password, CipherStrength strength)
    {
        if (strength == CipherStrength.None)
            return source;

        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        byte[][] keyIV = GlobalKeyIVCache.GetCryptoKeyIV(password, (int)strength);

        return source.Encrypt(startIndex, length, keyIV[KeyIndex], keyIV[IVIndex], strength);
    }

    /// <summary>
    /// Returns a binary array of encrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to encrypt.</param>
    /// <param name="key">Encryption key to use to encrypt data.</param>
    /// <param name="iv">Initialization vector to use to encrypt data.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting data.</param>
    /// <returns>An encrypted version of the source data.</returns>
    public static byte[] Encrypt(this byte[] source, byte[] key, byte[] iv, CipherStrength strength)
    {
        return source.Encrypt(0, source.Length, key, iv, strength);
    }

    /// <summary>
    /// Returns a binary array of encrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to encrypt.</param>
    /// <param name="startIndex">Offset into <paramref name="source"/> buffer.</param>
    /// <param name="length">Number of bytes in <paramref name="source"/> buffer to encrypt starting from <paramref name="startIndex"/> offset.</param>
    /// <param name="key">Encryption key to use to encrypt data.</param>
    /// <param name="iv">Initialization vector to use to encrypt data.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting data.</param>
    /// <returns>An encrypted version of the source data.</returns>
    public static byte[] Encrypt(this byte[] source, int startIndex, int length, byte[] key, byte[] iv, CipherStrength strength)
    {
        if (strength == CipherStrength.None)
            return source;

        Aes symmetricAlgorithm = Aes.Create();
        symmetricAlgorithm.KeySize = (int)strength;

        return symmetricAlgorithm.Encrypt(source, startIndex, length, key, iv);
    }

    /// <summary>
    /// Returns a stream of encrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Source stream that contains data to encrypt.</param>
    /// <param name="key">Encryption key to use to encrypt stream.</param>
    /// <param name="iv">Initialization vector to use to encrypt stream.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting stream.</param>
    /// <returns>An encrypted version of the source stream.</returns>
    /// <remarks>
    /// This returns a memory stream of the encrypted results, if the incoming stream is
    /// very large this will consume a large amount of memory.  In this case use the overload
    /// that takes the destination stream as a parameter instead.
    /// </remarks>
    public static MemoryStream Encrypt(this Stream source, byte[] key, byte[] iv, CipherStrength strength)
    {
        MemoryStream destination = new();

        source.Encrypt(destination, key, iv, strength);
        destination.Position = 0;

        return destination;
    }

    /// <summary>
    /// Encrypts input stream onto output stream for the given parameters.
    /// </summary>
    /// <param name="source">Source stream that contains data to encrypt.</param>
    /// <param name="destination">Destination stream used to hold encrypted data.</param>
    /// <param name="key">Encryption key to use to encrypt stream.</param>
    /// <param name="iv">Initialization vector to use to encrypt stream.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting stream.</param>
    /// <param name="progressHandler">Optional delegate to handle progress updates for encrypting large streams.</param>
    public static void Encrypt(this Stream source, Stream destination, byte[] key, byte[] iv, CipherStrength strength, Action<ProcessProgress<long>>? progressHandler = null)
    {
        ProcessProgressHandler<long>? progress = null;
        byte[] inBuffer = new byte[Standard.BufferSize];
        long total = 0;
        long length = -1;

        // Sends initial progress event.
        if (progressHandler is not null)
        {
            try
            {
                if (source.CanSeek)
                    length = source.Length;
            }
            catch
            {
                length = -1;
            }

            // Create a new progress handler to track encryption progress
            progress = new ProcessProgressHandler<long>(progressHandler, "Encrypt", length)
            { 
                Complete = 0
            };
        }

        // Reads initial buffer.
        int read = source.Read(inBuffer, 0, Standard.BufferSize);

        while (read > 0)
        {
            // Encrypts buffer.
            byte[] outBuffer = inBuffer.BlockCopy(0, read).Encrypt(key, iv, strength);

            // The destination encryption stream length does not have to be same as the input stream length, so we
            // prepend the final size of each encrypted buffer onto the destination output stream so that we can
            // safely decrypt the stream in a "chunked" fashion later.
            byte[] lengthBuffer = BitConverter.GetBytes(outBuffer.Length);
            destination.Write(lengthBuffer, 0, lengthBuffer.Length);
            destination.Write(outBuffer, 0, outBuffer.Length);

            // Updates encryption progress.
            if (progressHandler is not null)
            {
                total += read;
                progress!.Complete = total;
            }

            // Reads next buffer.
            read = source.Read(inBuffer, 0, Standard.BufferSize);
        }
    }

    /// <summary>
    /// Creates an encrypted file from source file data.
    /// </summary>
    /// <param name="sourceFileName">Source file name.</param>
    /// <param name="destinationFileName">Destination file name.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when encrypting file.</param>
    /// <param name="progressHandler">Optional delegate to handle progress updates for encrypting large files.</param>
    public static void EncryptFile(string sourceFileName, string destinationFileName, string password, CipherStrength strength, Action<ProcessProgress<long>> progressHandler)
    {
        using FileStream sourceFileStream = File.Open(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.Read), destFileStream = File.Create(destinationFileName);

        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        byte[][] keyIV = GlobalKeyIVCache.GetCryptoKeyIV(password, (int)strength);

        sourceFileStream.Encrypt(destFileStream, keyIV[KeyIndex], keyIV[IVIndex], strength, progressHandler);

        destFileStream.Flush();
        destFileStream.Close();
    }

    /// <summary>
    /// Decrypts a configuration setting in the format of "KeyName:EncodedValue" that was previously
    /// encrypted using the <see cref="Cipher.Encrypt(string, string, CipherStrength)"/> method
    /// using a <see cref="CipherStrength.Aes256"/> key size.
    /// </summary>
    /// <param name="value">Encoded configuration setting value.</param>
    /// <returns>Decoded configuration setting.</returns>
    /// <remarks>
    /// <para>
    /// If no key name is specified, value is assumed to not be encoded and is returned as is.
    /// </para>
    /// <para>
    /// It is recommended to use this method at the last possible moment, e.g., in stack variables,
    /// to avoid storing decrypted data in memory for longer periods of time.
    /// </para>
    /// </remarks>
    public static string ConfigDecrypt(this string value)
    {
        string[] parts = value.Split(':');

        return parts.Length != 2 ? value : parts[1].Decrypt(parts[0], CipherStrength.Aes256);
    }

    /// <summary>
    /// Returns a decrypted string from a Base64 encoded string of binary encrypted data from the given
    /// parameters.
    /// </summary>
    /// <param name="source">Source string to decrypt.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting string.</param>
    /// <returns>A decrypted version of the source string.</returns>
    public static string Decrypt(this string source, string password, CipherStrength strength)
    {
        return strength == CipherStrength.None ? source : Encoding.UTF8.GetString(Convert.FromBase64String(source).Decrypt(password, strength));
    }

    /// <summary>
    /// Returns a binary array of decrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to decrypt.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting data.</param>
    /// <returns>A decrypted version of the source data.</returns>
    public static byte[] Decrypt(this byte[] source, string password, CipherStrength strength)
    {
        return source.Decrypt(0, source.Length, password, strength);
    }

    /// <summary>
    /// Returns a binary array of decrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to decrypt.</param>
    /// <param name="startIndex">Offset into <paramref name="source"/> buffer.</param>
    /// <param name="length">Number of bytes in <paramref name="source"/> buffer to decrypt starting from <paramref name="startIndex"/> offset.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting data.</param>
    /// <returns>A decrypted version of the source data.</returns>
    public static byte[] Decrypt(this byte[] source, int startIndex, int length, string password, CipherStrength strength)
    {
        if (strength == CipherStrength.None)
            return source;

        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        byte[][] keyIV = GlobalKeyIVCache.GetCryptoKeyIV(password, (int)strength);

        return source.Decrypt(startIndex, length, keyIV[KeyIndex], keyIV[IVIndex], strength);
    }

    /// <summary>
    /// Returns a binary array of decrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to decrypt.</param>
    /// <param name="key">Encryption key to use to decrypt data.</param>
    /// <param name="iv">Initialization vector to use to decrypt data.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting data.</param>
    /// <returns>A decrypted version of the source data.</returns>
    public static byte[] Decrypt(this byte[] source, byte[] key, byte[] iv, CipherStrength strength)
    {
        return source.Decrypt(0, source.Length, key, iv, strength);
    }

    /// <summary>
    /// Returns a binary array of decrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Binary array of data to decrypt.</param>
    /// <param name="startIndex">Offset into <paramref name="source"/> buffer.</param>
    /// <param name="length">Number of bytes in <paramref name="source"/> buffer to decrypt starting from <paramref name="startIndex"/> offset.</param>
    /// <param name="key">Encryption key to use to decrypt data.</param>
    /// <param name="iv">Initialization vector to use to decrypt data.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting data.</param>
    /// <returns>A decrypted version of the source data.</returns>
    public static byte[] Decrypt(this byte[] source, int startIndex, int length, byte[] key, byte[] iv, CipherStrength strength)
    {
        if (strength == CipherStrength.None)
            return source;

        Aes symmetricAlgorithm = Aes.Create();
        symmetricAlgorithm.KeySize = (int)strength;

        return symmetricAlgorithm.Decrypt(source, startIndex, length, key, iv);
    }

    /// <summary>
    /// Returns a stream of decrypted data for the given parameters.
    /// </summary>
    /// <param name="source">Source stream that contains data to decrypt.</param>
    /// <param name="key">Encryption key to use to decrypt stream.</param>
    /// <param name="iv">Initialization vector to use to decrypt stream.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting stream.</param>
    /// <returns>A decrypted version of the source stream.</returns>
    /// <remarks>
    /// This returns a memory stream of the decrypted results, if the incoming stream is
    /// very large this will consume a large amount of memory.  In this case use the overload
    /// that takes the destination stream as a parameter instead.
    /// </remarks>
    public static MemoryStream Decrypt(this Stream source, byte[] key, byte[] iv, CipherStrength strength)
    {
        MemoryStream destination = new();

        source.Decrypt(destination, key, iv, strength);
        destination.Position = 0;

        return destination;
    }

    /// <summary>
    /// Decrypts input stream onto output stream for the given parameters.
    /// </summary>
    /// <param name="source">Source stream that contains data to decrypt.</param>
    /// <param name="destination">Destination stream used to hold decrypted data.</param>
    /// <param name="key">Encryption key to use to decrypt stream.</param>
    /// <param name="iv">Initialization vector to use to decrypt stream.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting stream.</param>
    /// <param name="progressHandler">Optional delegate to handle progress updates for decrypting large streams.</param>
    public static void Decrypt(this Stream source, Stream destination, byte[] key, byte[] iv, CipherStrength strength, Action<ProcessProgress<long>>? progressHandler = null)
    {
        ProcessProgressHandler<long>? progress = null;
        byte[] lengthBuffer = BitConverter.GetBytes(0);
        long total = 0;
        long length = -1;

        // Sends initial progress event.
        if (progressHandler is not null)
        {
            try
            {
                if (source.CanSeek)
                    length = source.Length;
            }
            catch
            {
                length = -1;
            }

            // Create a new progress handler to track decryption progress
            progress = new ProcessProgressHandler<long>(progressHandler, "Decrypt", length)
            { 
                Complete = 0
            };
        }

        // When the source stream was encrypted, it was known that the encrypted stream length did not have to be same
        // as the input stream length. We prepended the final size of each encrypted buffer onto the destination output
        // stream (now the input stream to this function), so that we could safely decrypt the stream in a "chunked"
        // fashion, hence the following:

        // Reads the size of the next buffer from the stream.
        int read = source.Read(lengthBuffer, 0, lengthBuffer.Length);

        while (read > 0)
        {
            // Converts the byte array containing the buffer size into an integer.
            int size = BitConverter.ToInt32(lengthBuffer, 0);

            if (size > 0)
            {
                // Creates and reads the next buffer.
                byte[] inBuffer = new byte[size];
                read = source.Read(inBuffer, 0, size);

                if (read > 0)
                {
                    // Decrypts buffer.
                    byte[] outBuffer = inBuffer.Decrypt(key, iv, strength);
                    destination.Write(outBuffer, 0, outBuffer.Length);

                    // Updates decryption progress.
                    if (progressHandler is not null)
                    {
                        total += read + lengthBuffer.Length;
                        progress!.Complete = total;
                    }
                }
            }

            // Reads the size of the next buffer from the stream.
            read = source.Read(lengthBuffer, 0, lengthBuffer.Length);
        }
    }

    /// <summary>
    /// Creates a decrypted file from source file data.
    /// </summary>
    /// <param name="sourceFileName">Source file name.</param>
    /// <param name="destinationFileName">Destination file name.</param>
    /// <param name="password">User password used for key lookup.</param>
    /// <param name="strength">Cryptographic strength to use when decrypting file.</param>
    /// <param name="progressHandler">Optional delegate to handle progress updates for decrypting large files.</param>
    public static void DecryptFile(string sourceFileName, string destinationFileName, string password, CipherStrength strength, Action<ProcessProgress<long>> progressHandler)
    {
        using FileStream sourceFileStream = File.Open(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.Read), destFileStream = File.Create(destinationFileName);

        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        byte[][] keyIV = GlobalKeyIVCache.GetCryptoKeyIV(password, (int)strength);

        sourceFileStream.Decrypt(destFileStream, keyIV[KeyIndex], keyIV[IVIndex], strength, progressHandler);

        destFileStream.Flush();
    }
}
