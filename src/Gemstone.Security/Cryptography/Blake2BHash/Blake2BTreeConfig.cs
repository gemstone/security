﻿// BLAKE2 reference source code package - C# implementation

// Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
namespace Gemstone.Security.Cryptography.Blake2BHash
{
    /// <summary>
    /// Parameters for the tree hash.
    /// </summary>
    public sealed class Blake2BTreeConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Blake2BTreeConfig"/> class.
        /// </summary>
        public Blake2BTreeConfig()
        {
            IntermediateHashSize = 64;
        }

        /// <summary>
        /// Gets or sets the intermediate hash size.
        /// </summary>
        public int IntermediateHashSize { get; set; }

        /// <summary>
        /// Gets or sets the tree maximum height.
        /// </summary>
        public int MaxHeight { get; set; }

        /// <summary>
        /// Gets or sets the tree leaf size.
        /// </summary>
        public long LeafSize { get; set; }

        /// <summary>
        /// Gets or sets the tree fan out value.
        /// </summary>
        public int FanOut { get; set; }

        // ReSharper disable once UnusedMember.Global

        /// <summary>
        /// Create an instance of the <see cref="Blake2BTreeConfig"/> for parallel hash computation.
        /// </summary>
        /// <param name="parallelism">
        /// The amount of parallelism to invoke when generating the hash.
        /// </param>
        /// <returns>
        /// An instance of the <see cref="Blake2BTreeConfig"/> suitable for generating a hash.
        /// </returns>
        public static Blake2BTreeConfig CreateInterleaved(int parallelism)
        {
            return new Blake2BTreeConfig
            {
                FanOut = parallelism,
                MaxHeight = 2,
                IntermediateHashSize = 64,
            };
        }
    }
}
