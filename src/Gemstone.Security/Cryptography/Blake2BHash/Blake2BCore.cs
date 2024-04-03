// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
/*
  Based on BlakeSharp
  by Dominik Reichl <dominik.reichl@t-online.de>
  Web: http://www.dominik-reichl.de/
  If you're using this class, it would be nice if you'd mention
  me somewhere in the documentation of your program, but it's
  not required.

  BLAKE was designed by Jean-Philippe Aumasson, Luca Henzen,
  Willi Meier and Raphael C.-W. Phan.
  BlakeSharp was derived from the reference C implementation.
*/

using System;

namespace Gemstone.Security.Cryptography.Blake2BHash
{
    /// <summary>
    /// The core of the Blake2 hash.
    /// </summary>
    public sealed partial class Blake2BCore : IDisposable
    {
        private const int BlockSizeInBytes = 128;

        private const ulong Iv0 = 0x6A09E667F3BCC908UL;
        private const ulong Iv1 = 0xBB67AE8584CAA73BUL;
        private const ulong Iv2 = 0x3C6EF372FE94F82BUL;
        private const ulong Iv3 = 0xA54FF53A5F1D36F1UL;
        private const ulong Iv4 = 0x510E527FADE682D1UL;
        private const ulong Iv5 = 0x9B05688C2B3E6C1FUL;
        private const ulong Iv6 = 0x1F83D9ABFB41BD6BUL;
        private const ulong Iv7 = 0x5BE0CD19137E2179UL;

        private readonly ZeroedBuffer<byte> m_buf;
        private readonly ZeroedBuffer<ulong> m_mbuf;
        private readonly ZeroedBuffer<ulong> m_hbuf;
        private bool m_isInitialized;
        private int m_bufferFilled;
        private ulong m_counter0;
        private ulong m_counter1;
        private ulong m_finalizationFlag0;
        private ulong m_finalizationFlag1;

        /// <summary>
        /// Initializes a new instance of the <see cref="Blake2BCore"/> class.
        /// </summary>
        public Blake2BCore()
        {
            m_buf = new ZeroedBuffer<byte>(128);
            m_mbuf = new ZeroedBuffer<ulong>(16);
            m_hbuf = new ZeroedBuffer<ulong>(8);
        }

        /// <summary>
        /// Convert a big-endian buffer into a <see cref="ulong"/>.
        /// </summary>
        /// <param name="buf">Buffer holding an 8-byte big-endian ulong.</param>
        /// <param name="offset">Offset into the buffer to start reading the ulong.</param>
        /// <returns>The parsed ulong.</returns>
        /// <remarks>
        /// No checking is done to verify that an 8-byte value can be read from <paramref name="buf"/> at <paramref name="offset"/>.
        /// </remarks>
        public static ulong BytesToUInt64(byte[] buf, int offset)
        {
            return
                ((ulong)buf[offset + 7] << (7 * 8)) |
                ((ulong)buf[offset + 6] << (6 * 8)) |
                ((ulong)buf[offset + 5] << (5 * 8)) |
                ((ulong)buf[offset + 4] << (4 * 8)) |
                ((ulong)buf[offset + 3] << (3 * 8)) |
                ((ulong)buf[offset + 2] << (2 * 8)) |
                ((ulong)buf[offset + 1] << (1 * 8)) |
                buf[offset];
        }

        /// <summary>
        /// Store a ulong into a byte buffer as big-endian.
        /// </summary>
        /// <param name="value">The ulong to store.</param>
        /// <param name="buf">The buffer to load the 8-byte value into.</param>
        /// <param name="offset">The offset to start <paramref name="value"/> at in <paramref name="buf"/>.</param>
        /// <remarks>
        /// No checking is done to validate the buffer can store <paramref name="value"/> at <paramref name="offset"/>.
        /// </remarks>
        public static void UInt64ToBytes(ulong value, byte[] buf, int offset)
        {
            buf[offset + 7] = (byte)(value >> (7 * 8));
            buf[offset + 6] = (byte)(value >> (6 * 8));
            buf[offset + 5] = (byte)(value >> (5 * 8));
            buf[offset + 4] = (byte)(value >> (4 * 8));
            buf[offset + 3] = (byte)(value >> (3 * 8));
            buf[offset + 2] = (byte)(value >> (2 * 8));
            buf[offset + 1] = (byte)(value >> (1 * 8));
            buf[offset] = (byte)value;
        }

        /// <summary>
        /// Initialize the hash.
        /// </summary>
        /// <param name="config">8-element configuration array.</param>
        public void Initialize(ulong[] config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            if (config.Length != 8)
                throw new ArgumentException("config length must be 8 words", nameof(config));

            m_isInitialized = true;

            m_hbuf[0] = Iv0;
            m_hbuf[1] = Iv1;
            m_hbuf[2] = Iv2;
            m_hbuf[3] = Iv3;
            m_hbuf[4] = Iv4;
            m_hbuf[5] = Iv5;
            m_hbuf[6] = Iv6;
            m_hbuf[7] = Iv7;

            m_counter0 = 0;
            m_counter1 = 0;
            m_finalizationFlag0 = 0;
            m_finalizationFlag1 = 0;

            m_bufferFilled = 0;

            Array.Clear(m_buf.Buffer, 0, m_buf.Buffer.Length);

            for (int i = 0; i < 8; i++) m_hbuf[i] ^= config[i];
        }

        /// <summary>
        /// Update the hash state.
        /// </summary>
        /// <param name="array">
        /// Data to use to update the hash state.
        /// </param>
        /// <param name="start">
        /// Index of the first byte in <paramref name="array"/> to use.
        /// </param>
        /// <param name="count">
        /// Number of bytes in <paramref name="array"/> to use.
        /// </param>
        public void HashCore(byte[] array, int start, int count)
        {
            if (!m_isInitialized)
                throw new InvalidOperationException("Not initialized");

            if (array == null)
                throw new ArgumentNullException(nameof(array));

            if (start < 0)
                throw new ArgumentOutOfRangeException(nameof(start));

            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));

            if (start + (long)count > array.Length)
                throw new ArgumentOutOfRangeException(nameof(count), $"Expected start+count <= array.Length, got {start}+{count} > {array.Length}");

            int offset = start;
            int bufferRemaining = BlockSizeInBytes - m_bufferFilled;

            if (m_bufferFilled > 0 && count > bufferRemaining)
            {
                Array.Copy(array, offset, m_buf.Buffer, m_bufferFilled, bufferRemaining);
                m_counter0 += BlockSizeInBytes;
                
                if (m_counter0 == 0)
                    m_counter1++;

                Compress(m_buf.Buffer, 0);
                
                offset += bufferRemaining;
                count -= bufferRemaining;
                
                m_bufferFilled = 0;
            }

            while (count > BlockSizeInBytes)
            {
                m_counter0 += BlockSizeInBytes;
                
                if (m_counter0 == 0)
                    m_counter1++;

                Compress(array, offset);
                
                offset += BlockSizeInBytes;
                count -= BlockSizeInBytes;
            }

            if (count <= 0)
                return;

            Array.Copy(array, offset, m_buf.Buffer, m_bufferFilled, count);
            m_bufferFilled += count;
        }

        /// <summary>
        /// Compute the hash.
        /// </summary>
        /// <param name="hash">
        /// Loaded with the hash.
        /// </param>
        /// <returns>
        /// <paramref name="hash"/>.
        /// </returns>
        public byte[] HashFinal(byte[] hash)
        {
            return HashFinal(hash, false);
        }

        /// <summary>
        /// Compute the hash.
        /// </summary>
        /// <param name="hash">
        /// Loaded with the hash.
        /// </param>
        /// <param name="isEndOfLayer">
        /// True to signal the last node of a layer in tree-hashing mode; false otherwise.
        /// </param>
        /// <returns>
        /// <paramref name="hash"/>.
        /// </returns>
        public byte[] HashFinal(byte[] hash, bool isEndOfLayer)
        {
            if (!m_isInitialized)
                throw new InvalidOperationException("Not initialized");

            if (hash.Length != 64)
                throw new ArgumentException($"Invalid hash length, got {hash.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)}, expected 64", nameof(hash));

            m_isInitialized = false;

            // Last compression
            m_counter0 += (uint)m_bufferFilled;
            m_finalizationFlag0 = ulong.MaxValue;

            if (isEndOfLayer) 
                m_finalizationFlag1 = ulong.MaxValue;

            for (int i = m_bufferFilled; i < m_buf.Buffer.Length; i++) 
                m_buf[i] = 0;

            Compress(m_buf.Buffer, 0);

            // Output
            for (int i = 0; i < 8; ++i) 
                UInt64ToBytes(m_hbuf[i], hash, i << 3);

            return hash;
        }

        /// <summary>
        /// Return the hash.
        /// </summary>
        /// <returns>
        /// The 64-byte hash.
        /// </returns>
        public byte[] HashFinal()
        {
            return HashFinal(false);
        }

        /// <summary>
        /// Return the hash.
        /// </summary>
        /// <param name="isEndOfLayer">
        /// True to signal the last node of a layer in tree-hashing mode; false otherwise.
        /// </param>
        /// <returns>
        /// The 64-byte hash.
        /// </returns>
        public byte[] HashFinal(bool isEndOfLayer)
        {
            byte[] hash = new byte[64];
            
            HashFinal(hash, isEndOfLayer);
            
            return hash;
        }

        /// <summary>
        /// Release unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            m_hbuf.Dispose();
            m_mbuf.Dispose();
            m_buf.Dispose();
        }

        partial void Compress(byte[] block, int start);
    }
}
