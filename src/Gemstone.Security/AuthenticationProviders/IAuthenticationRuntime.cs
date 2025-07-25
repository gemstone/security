//******************************************************************************************************
//  IAuthenticationRuntime.cs - Gbtc
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
//  07/24/2025 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

using System.Collections.Generic;
using System.Security.Claims;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Represents a provider of runtime configuration for Gemstone authentication.
/// </summary>
public interface IAuthenticationRuntime
{
    /// <summary>
    /// Gets the list of identities for active authentication provider.
    /// </summary>
    /// <returns>The list of provider identities.</returns>
    IEnumerable<string> GetProviderIdentities();

    /// <summary>
    /// Assigns claims to the user represented by the principal.
    /// </summary>
    /// <param name="providerIdentity">Identity of the user's authentication provider</param>
    /// <param name="principal">The principal that represents the user</param>
    /// <returns>The list of claims assigned to the user.</returns>
    IEnumerable<Claim> GetAssignedClaims(string providerIdentity, ClaimsPrincipal principal);
}
