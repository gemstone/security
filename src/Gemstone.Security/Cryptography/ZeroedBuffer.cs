//******************************************************************************************************
//  ZeroedBuffer.cs - Gbtc
//
//  Copyright © 2024, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the MIT License (MIT), the "License"; you may not use this
//  file except in compliance with the License. You may obtain a copy of the License at:
//
//      http://opensource.org/licenses/MIT
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  03/27/2024 - Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Diagnostics;
using Gemstone.ArrayExtensions;

namespace Gemstone.Security.Cryptography;

/// <summary>
/// Represents a buffer that is zeroed when disposed.
/// </summary>
/// <remarks>
/// <para>
/// Initializes a new instance of the <see cref="ZeroedBuffer{T}"/> class.
/// </para>
/// <para>
/// If type <typeparamref name="T"/> is a reference type, the buffer will be zeroed by setting all elements to <c>null</c>.
/// </para>
/// </remarks>
/// <param name="size">The number of elements in the array.</param>
public sealed class ZeroedBuffer<T>(int size) : IDisposable
{
    private bool m_disposed;

#if DEBUG
    ~ZeroedBuffer()
    {
        Debug.Assert(m_disposed, $"{nameof(ZeroedBuffer<T>)} was not disposed.");
    }
#endif

    /// <summary>
    /// Gets the buffer array instance.
    /// </summary>
    public T[] Buffer { get; } = new T[size];

    /// <summary>
    /// Accesses element in the <see cref="ZeroedBuffer{T}"/>> by reference.
    /// </summary>
    /// <param name="index">The index of the element to access.</param>
    public ref T this[int index] => ref Buffer[index];

    /// <summary>
    /// Zero buffer and release resources.
    /// </summary>
    public void Dispose()
    {
        if (m_disposed)
            return;

        Buffer.Zero();
        m_disposed = true;
    }
}
