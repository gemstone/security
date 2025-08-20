//******************************************************************************************************
//  IAuthenticationProvider.cs - Gbtc
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

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Represents a provider of claims for an authentication provider.
/// </summary>
public interface IAuthenticationProvider
{
    /// <summary>
    /// Gets the identity of the user represented by the principal.
    /// </summary>
    /// <param name="principal">The principal that represents the user</param>
    /// <returns>The user's identity.</returns>
    string GetIdentity(ClaimsPrincipal principal);

    /// <summary>
    /// Get the types of claims supported by the authentication provider.
    /// </summary>
    /// <returns>The types of claims supported by the authentication provider.</returns>
    IEnumerable<IClaimType> GetClaimTypes();

    /// <summary>
    /// Find user accounts that can be authenticated by the authentication provider.
    /// </summary>
    /// <param name="searchText">Text used to narrow the results of the search for users</param>
    /// <returns>A collection of users matching the search text.</returns>
    /// <remarks>
    /// Search text can include asterisks as wildcards.
    /// To include a literal asterisk, use backslash as the escape character.
    /// A literal backslash can be escaped by another backslash.
    /// Any other character escaped by a backslash matches the character;
    /// the backslash will be removed.
    /// </remarks>
    IEnumerable<IUserAccount> FindUsers(string searchText);

    /// <summary>
    /// Find claims that can be returned by the authentication provider.
    /// </summary>
    /// <param name="claimType">The type of claim to search for</param>
    /// <param name="searchText">Text used to narrow the results for the search for claims</param>
    /// <returns>A collection of claims matching the search text.</returns>
    /// <remarks>
    /// Search text can include asterisks as wildcards.
    /// To include a literal asterisk, use backslash as the escape character.
    /// A literal backslash can be escaped by another backslash.
    /// Any other character escaped by a backslash matches the character;
    /// the backslash will be removed.
    /// </remarks>
    IEnumerable<IProviderClaim> FindClaims(string claimType, string searchText);
}

/// <summary>
/// Extension methods for setting up an <see cref="IAuthenticationProvider"/>.
/// </summary>
public static class AuthenticationProviderExtensions
{
    /// <summary>
    /// Adds an authentication provider as a singleton service.
    /// </summary>
    /// <typeparam name="T">The type of authentication provider to be instantiated as the singleton instance</typeparam>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddAuthenticationProvider<T>(this IServiceCollection services, string identity) where T : class, IAuthenticationProvider
    {
        return services.AddKeyedSingleton<IAuthenticationProvider, T>(identity);
    }

    /// <summary>
    /// Adds an authentication provider as a singleton service.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <param name="provider">The provider instance to be added as the singleton service</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddAuthenticationProvider(this IServiceCollection services, string identity, IAuthenticationProvider provider)
    {
        return services.AddKeyedSingleton(identity, provider);
    }

    /// <summary>
    /// Adds the authentication provider as a singleton service.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <param name="providerFactory">Factory function used to instantiating the singleton instance</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddAuthenticationProvider(this IServiceCollection services, string identity, Func<IServiceProvider, IAuthenticationProvider> providerFactory)
    {
        return services.AddKeyedSingleton(identity, providerFactory);
    }
}
