//******************************************************************************************************
//  APIAUthenticationProvider.cs - Gbtc
//
//  Copyright © 2026, Grid Protection Alliance.  All Rights Reserved.
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
//  07/09/2026 - C. Lackner
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Options for the <see cref="APIAuthenticationProvider"/> class.
/// </summary>
public class APIAuthenticationProviderOptions
{
    /// <summary>
    /// Function that validates a Token
    /// </summary>
    public Func<string, APIToken?>? ValidateToken { get; set; }

}

public class APIToken
{
    public string Name { get; set; }
    public DateTime Expiration { get; set; }

    public Claim[] Claims { get; set; } 
}


public class APIAuthenticationProvider 
{
    private readonly RequestDelegate _next;
    private readonly APIAuthenticationProviderOptions Settings;
    public APIAuthenticationProvider(RequestDelegate next, APIAuthenticationProviderOptions options)
    {
        _next = next;
        Settings = options;
    }
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            string bearerToken = authHeader.ToString();

            if (bearerToken.StartsWith("Bearer ", System.StringComparison.OrdinalIgnoreCase))
            {
                string token = bearerToken.Substring("Bearer ".Length).Trim();
                APIToken? resolvedToken = Settings.ValidateToken?.Invoke(token);
                if (resolvedToken == null || resolvedToken.Expiration < DateTime.UtcNow)
                {
                    await _next(context);
                    return;
                }
                ClaimsIdentity identity = new("APIAuthentication");
                identity.AddClaim(new(ClaimTypes.Name, resolvedToken.Name));
                identity.AddClaims(resolvedToken.Claims);
                context.User = new(identity);
                await _next(context);
            }
        }
    }
}

