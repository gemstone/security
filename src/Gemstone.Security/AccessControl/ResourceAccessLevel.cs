//******************************************************************************************************
//  ResourceAccessLevel.cs - Gbtc
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
//  02/24/2025 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

using System.Linq;
using System.Security.Claims;

namespace Gemstone.Security.AccessControl;

/// <summary>
/// Represents the default access levels that can apply to a resource.
/// </summary>
public enum ResourceAccessLevel
{
    /// <summary>
    /// View-only access (read, status, ...)
    /// </summary>
    View,

    /// <summary>
    /// Basic level of configuration (start/stop adapters, update connection strings, ...)
    /// </summary>
    Edit,

    /// <summary>
    /// Administrative level of configuration (users, roles, permissions, config files, ...)
    /// </summary>
    Admin,

    /// <summary>
    /// Dangerous level of configuration that can be enabled
    /// for convenience or necessity (upload files to server, ...)
    /// </summary>
    Special
}

/// <summary>
/// Extension methods for resource access.
/// </summary>
public static class ResourceAccessExtensions
{
    /// <summary>
    /// Determines whether the user has access to a given resource.
    /// </summary>
    /// <param name="user">The user who is requesting access</param>
    /// <param name="resourceType">The type of resource being requested</param>
    /// <param name="resourceName">The identity of the requested resource</param>
    /// <param name="access">The levels of access that would satisfy the request</param>
    /// <returns>A value indicating whether permission is granted or denied.</returns>
    public static bool HasAccessTo(this ClaimsPrincipal user, string resourceType, string resourceName, params ResourceAccessLevel[] access)
    {
        return access
            .Select(level => user.HasAccessTo(resourceType, resourceName, level))
            .Any(b => b);
    }

    /// <summary>
    /// Determines whether the user has access to a given resource.
    /// </summary>
    /// <param name="user">The user who is requesting access</param>
    /// <param name="resourceType">The type of resource being requested</param>
    /// <param name="resourceName">The identity of the requested resource</param>
    /// <param name="access">The level of access requested</param>
    /// <returns>A value indicating whether permission is granted or denied.</returns>
    public static bool HasAccessTo(this ClaimsPrincipal user, string resourceType, string resourceName, ResourceAccessLevel access)
    {
        const string AllowClaim = "Gemstone.ResourceAccess.Allow";
        const string DenyClaim = "Gemstone.ResourceAccess.Deny";
        const string RoleClaim = "Gemstone.Role";

        string claimValue = $"{resourceType} {resourceName} {access}";

        bool IsDenied() =>
            user.HasClaim(DenyClaim, claimValue);

        bool IsAllowed() =>
            user.HasClaim(AllowClaim, claimValue) ||
            user.HasClaim(RoleClaim, $"{access}");

        return !IsDenied() && IsAllowed();
    }
}
