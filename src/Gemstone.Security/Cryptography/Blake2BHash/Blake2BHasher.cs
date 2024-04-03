// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>
// Modified in 2016 by Michael Heyman for sensitive information

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

using System;

namespace Gemstone.Security.Cryptography.Blake2BHash
{
    /// <summary>
    /// Init/Update/Final for Blake2 hash.
    /// </summary>
    internal class Blake2BHasher : Hasher
    {
        private static readonly Blake2BConfig s_defaultConfig = new();

        private readonly Blake2BCore m_core;

        private readonly ZeroedBuffer<ulong> m_rawConfig;

        private readonly ZeroedBuffer<byte>? m_key;

        private readonly byte[]? m_defaultOutputBuffer;

        private readonly int m_outputSizeInBytes;

        private bool m_disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="Blake2BHasher"/> class.
        /// </summary>
        /// <param name="config">The configuration to use; may be null to use the default Blake2 configuration.</param>
        public Blake2BHasher(Blake2BConfig? config)
        {
            config ??= s_defaultConfig;
            m_core = new Blake2BCore();
            m_rawConfig = Blake2IvBuilder.ConfigB(config, null);
            
            if (config.Key != null && config.Key.Length != 0)
            {
                m_key = new ZeroedBuffer<byte>(128);
                Array.Copy(config.Key, m_key.Buffer, config.Key.Length);
            }

            m_outputSizeInBytes = config.OutputSizeInBytes;
            m_defaultOutputBuffer = config.Result64ByteBuffer;
            
            Init();
        }

        /// <summary>
        /// Initialize the hasher. The hasher is initialized upon construction but this can be used
        /// to reinitialize in order to reuse the hasher.
        /// </summary>
        /// <exception cref="ObjectDisposedException">When called after being disposed.</exception>
        public sealed override void Init()
        {
            if (m_disposed)
                throw new ObjectDisposedException("Called Blake2BHasher.Init() on disposed object");

            m_core.Initialize(m_rawConfig.Buffer);
            
            if (m_key != null) 
                m_core.HashCore(m_key.Buffer, 0, m_key.Buffer.Length);
        }

        /// <summary>
        /// Update the hasher with more bytes of data.
        /// </summary>
        /// <param name="data">Buffer holding the data to update with.</param>
        /// <param name="start">The offset into the buffer of the data to update the hasher with.</param>
        /// <param name="count">The number of bytes starting at <paramref name="start"/> to update the hasher with.</param>
        /// <exception cref="ObjectDisposedException">When called after being disposed.</exception>
        public override void Update(byte[] data, int start, int count)
        {
            if (m_disposed)
                throw new ObjectDisposedException("Called Blake2BHasher.Update() on disposed object");

            m_core.HashCore(data, start, count);
        }

        /// <summary>
        /// Either returns <see cref="Blake2BConfig"/>.<see cref="Blake2BConfig.Result64ByteBuffer"/>
        /// or a new buffer of <see cref="Blake2BConfig"/>.<see cref="Blake2BConfig.OutputSizeInBytes"/>
        /// if no <see cref="Blake2BConfig.Result64ByteBuffer"/> was given.
        /// </summary>
        /// <returns>
        /// Either the final Blake2 hash or the <see cref="Blake2BConfig.Result64ByteBuffer"/>. If
        /// <see cref="Blake2BConfig.Result64ByteBuffer"/> is non-null and <see cref="Blake2BConfig"/>.<see
        /// cref="Blake2BConfig.OutputSizeInBytes"/> is less than 64, then the actual Blake2 hash
        /// is the first <see cref="Blake2BConfig.OutputSizeInBytes"/> of the <see
        /// cref="Blake2BConfig.Result64ByteBuffer"/> buffer.
        /// </returns>
        public override byte[] Finish()
        {
            if (m_disposed)
                throw new ObjectDisposedException("Called Blake2BHasher.Finish() on disposed object");

            if (m_defaultOutputBuffer != null)
                return m_core.HashFinal(m_defaultOutputBuffer);

            byte[] fullResult = m_core.HashFinal();

            if (m_outputSizeInBytes == fullResult.Length)
                return fullResult;

            byte[] result = new byte[m_outputSizeInBytes];
            Array.Copy(fullResult, result, result.Length);
            
            return result;
        }

        /// <summary>
        /// Disposes resources if <paramref name="disposing"/> is true.
        /// </summary>
        /// <param name="disposing">
        /// Set to true if disposing.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if (m_disposed)
                return;

            m_key?.Dispose();
            m_rawConfig.Dispose();
            m_core.Dispose();
            m_disposed = true;
            
            base.Dispose(disposing);
        }
    }
}
