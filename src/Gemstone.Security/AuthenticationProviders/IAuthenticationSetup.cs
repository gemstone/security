//******************************************************************************************************
//  IAuthenticationSetup.cs - Gbtc
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
/// Represents the provider of setup data for Gemstone authentication.
/// </summary>
public interface IAuthenticationSetup
{
    /// <summary>
    /// Gets the list of provider identities defined in the setup data.
    /// </summary>
    /// <returns>The list of provider identities.</returns>
    IEnumerable<string> GetProviderIdentities();

    /// <summary>
    /// Gets the list of user identities for a given provider defined in the setup data.
    /// </summary>
    /// <param name="providerIdentity">The identity of the authentication provider</param>
    /// <returns>The list of user identities.</returns>
    IEnumerable<string> GetUserIdentities(string providerIdentity);

    /// <summary>
    /// Gets a list of claims assigned to a given user.
    /// </summary>
    /// <param name="providerIdentity">The identity of the authentication provider</param>
    /// <param name="userIdentity">The identity of the user</param>
    /// <returns>The list of claims assigned to the user.</returns>
    IEnumerable<Claim> GetUserClaims(string providerIdentity, string userIdentity);

    /// <summary>
    /// Gets a list of mappings between claims provided by the authentication
    /// provider and claims assigned to users with matching claims.
    /// </summary>
    /// <param name="providerIdentity">The identity of the authentication provider</param>
    /// <returns>The list of mappings between provider claims and assigned claims.</returns>
    IEnumerable<(Claim Match, Claim Assigned)> GetProviderClaims(string providerIdentity);
}
