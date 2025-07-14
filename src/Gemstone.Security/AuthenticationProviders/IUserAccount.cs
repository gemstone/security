//******************************************************************************************************
//  IUserAccount.cs - Gbtc
//
//  Copyright © 2025, Grid Protection Alliance.  All Rights Reserved.
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
//  07/11/2025 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Represents a user account that identifies a user who logs in via an authentication provider.
/// </summary>
public interface IUserAccount
{
    /// <summary>
    /// Gets a string identifier that uniquely identifies the user.
    /// </summary>
    string Identity { get; }

    /// <summary>
    /// Gets the name of the user's account.
    /// </summary>
    string AccountName { get; }

    /// <summary>
    /// Gets the given name of the user.
    /// </summary>
    string? FirstName { get; }

    /// <summary>
    /// Gets the surname of the user.
    /// </summary>
    string? LastName { get; }
}
