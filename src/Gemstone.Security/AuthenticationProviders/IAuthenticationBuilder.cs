//******************************************************************************************************
//  IAuthenticationBuilder.cs - Gbtc
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Gemstone.Collections.CollectionExtensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Represents a builder for Gemstone authentication.
/// </summary>
public interface IAuthenticationBuilder
{
    /// <summary>
    /// Adds a claim for users with a matching claim.
    /// </summary>
    /// <param name="providerIdentity">The identity of the authentication provider</param>
    /// <param name="matchingClaim">Users with this claim will receive the assigned claim</param>
    /// <param name="assignedClaim">The claim to be assigned to users</param>
    /// <returns>The authentication builder.</returns>
    public IAuthenticationBuilder AddProviderClaim(string providerIdentity, Claim matchingClaim, Claim assignedClaim);
}

/// <summary>
/// Extensions for the authentication builder.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    private class AuthenticationBuilder : IAuthenticationBuilder
    {
        public AuthenticationSetup Setup { get; } = new();

        public IAuthenticationBuilder AddProviderClaim(string providerIdentity, Claim matchingClaim, Claim assignedClaim)
        {
            List<(Claim, Claim)> claims = Setup.ProviderClaims.GetOrAdd(providerIdentity, _ => []);
            claims.Add((matchingClaim, assignedClaim));
            return this;
        }
    }

    private class AuthenticationSetup : IAuthenticationSetup
    {
        internal Dictionary<string, List<(Claim, Claim)>> ProviderClaims { get; } = [];

        public IEnumerable<string> GetProviderIdentities()
        {
            return ProviderClaims.Keys;
        }

        public IEnumerable<(Claim Match, Claim Assigned)> GetProviderClaims(string providerIdentity)
        {
            return ProviderClaims.TryGetValue(providerIdentity, out List<(Claim, Claim)>? claims)
                ? claims.AsEnumerable() : [];
        }
    }

    private class AuthenticationRuntime(IServiceCollection services, IAuthenticationSetup setup, Func<string, IAuthenticationProvider?> providerLookup) : IAuthenticationRuntime
    {
        private IServiceCollection Services { get; } = services;
        private IAuthenticationSetup Setup { get; } = setup;
        private Func<string, IAuthenticationProvider?> ProviderLookup { get; } = providerLookup;

        public IEnumerable<string> GetProviderIdentities()
        {
            return Services
                .Where(descriptor => descriptor.IsKeyedService)
                .Where(descriptor => descriptor.ServiceType == typeof(IAuthenticationProvider))
                .Select(descriptor => descriptor.ServiceKey as string)
                .Where(key => key is not null)!;
        }

        public IEnumerable<Claim> GetAssignedClaims(string providerIdentity, ClaimsPrincipal principal)
        {
            const string ProviderIdentityClaim = "Gemstone.ProviderIdentity";
            const string UserIdentityClaim = "Gemstone.UserIdentity";

            IAuthenticationProvider? provider = ProviderLookup(providerIdentity);

            if (provider is null)
                return [];

            string userIdentity = provider.GetIdentity(principal);

            IEnumerable<Claim> providerClaims = Setup
                .GetProviderClaims(providerIdentity)
                .Join(principal.Claims, ToKey, ToKey, (providerClaim, _) => providerClaim.Assigned)
                .Prepend(new(UserIdentityClaim, userIdentity))
                .Prepend(new(ProviderIdentityClaim, providerIdentity));

            return providerClaims;
        }

        private static (string, string) ToKey((Claim Match, Claim) tuple)
        {
            return ToKey(tuple.Match);
        }

        private static (string, string) ToKey(Claim claim)
        {
            return (claim.Type, claim.Value);
        }
    }

    /// <summary>
    /// Adds the Gemstone authentication runtime to the services collection.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddGemstoneAuthentication<T>(this IServiceCollection services) where T : class, IAuthenticationSetup
    {
        services.TryAddSingleton<IAuthenticationRuntime>(provider => CreateAuthenticationRuntime(services, provider));
        services.TryAddSingleton<IAuthenticationSetup, T>();
        return services;
    }

    /// <summary>
    /// Adds the Gemstone authentication runtime to the services collection.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="configure">Method to configure the runtime</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddGemstoneAuthentication(this IServiceCollection services, Action<IAuthenticationBuilder> configure)
    {
        services.TryAddSingleton<IAuthenticationRuntime>(provider => CreateAuthenticationRuntime(services, provider));

        services.TryAddSingleton<IAuthenticationSetup>(_ =>
        {
            AuthenticationBuilder builder = new();
            configure(builder);
            return builder.Setup;
        });

        return services;
    }

    private static AuthenticationRuntime CreateAuthenticationRuntime(IServiceCollection serviceCollection, IServiceProvider serviceProvider)
    {
        IAuthenticationSetup setup = serviceProvider.GetRequiredService<IAuthenticationSetup>();
        return new(serviceCollection, setup, findProvider);

        IAuthenticationProvider? findProvider(string providerIdentity) =>
            serviceProvider.GetKeyedService<IAuthenticationProvider>(providerIdentity);
    }
}
