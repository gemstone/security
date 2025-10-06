//******************************************************************************************************
//  ResourceAccessType.cs - Gbtc
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

using System;
using System.Security.Claims;

namespace Gemstone.Security.AccessControl;

/// <summary>
/// Represents the default access types that can apply to a resource.
/// </summary>
public enum ResourceAccessType
{
    /// <summary>
    /// Create a new instance of the resource.
    /// </summary>
    Create,

    /// <summary>
    /// Read information about existing resources.
    /// </summary>
    Read,

    /// <summary>
    /// Update information associated with existing resources.
    /// </summary>
    Update,

    /// <summary>
    /// Delete a resource from existence.
    /// </summary>
    Delete,

    /// <summary>
    /// A level of access that cannot be satisfied.
    /// </summary>
    None,

    /// <summary>
    /// The default level of access, as defined by the resource type.
    /// </summary>
    Default,

    /// <summary>
    /// No resource access type was explicitly specified.
    /// </summary>
    NotSpecified
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
    /// <param name="access">The level of access requested</param>
    /// <returns>A value indicating whether permission is granted or denied.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    ///   <paramref name="access"/> is not one of:
    ///   <list type="bullet">
    ///     <item><see cref="ResourceAccessType.Create"/></item>
    ///     <item><see cref="ResourceAccessType.Read"/></item>
    ///     <item><see cref="ResourceAccessType.Update"/></item>
    ///     <item><see cref="ResourceAccessType.Delete"/></item>
    ///     <item><see cref="ResourceAccessType.None"/></item>
    ///   </list>
    /// </exception>
    public static bool HasAccessTo(this ClaimsPrincipal user, string resourceType, string resourceName, ResourceAccessType access)
    {
        ThrowIfNotValid(access);

        const string AllowClaim = "Gemstone.ResourceAccess.Allow";
        const string DenyClaim = "Gemstone.ResourceAccess.Deny";
        const string BaseClaim = "Gemstone.ResourceAccess.Default";

        if (access == ResourceAccessType.None)
            return false;

        string claimValue = $"{resourceType} {resourceName} {access}";

        bool IsDenied() =>
            user.HasClaim(DenyClaim, claimValue);

        bool IsAllowed() =>
            user.HasClaim(AllowClaim, claimValue) ||
            user.HasClaim(BaseClaim, $"{access}");

        return !IsDenied() && IsAllowed();
    }

    private static void ThrowIfNotValid(ResourceAccessType access)
    {
        switch (access)
        {
            case ResourceAccessType.Create:
            case ResourceAccessType.Read:
            case ResourceAccessType.Update:
            case ResourceAccessType.Delete:
            case ResourceAccessType.None:
                return;
        }

        string message = $"Invalid access type for resource: {access}";
        throw new ArgumentOutOfRangeException(nameof(access), access, message);
    }
}
