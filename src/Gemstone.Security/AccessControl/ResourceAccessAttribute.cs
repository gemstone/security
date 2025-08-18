//******************************************************************************************************
//  ResourceAccessAttribute.cs - Gbtc
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
//  07/29/2025 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Gemstone.Security.AccessControl;

/// <summary>
/// Annotation to assign access levels to a resource represented by a class, method, property, etc.
/// </summary>
/// <param name="name">The name of the resource</param>
/// <param name="access">The level of permission required to access the resource</param>
[AttributeUsage(AttributeTargets.All, Inherited = true, AllowMultiple = false)]
public class ResourceAccessAttribute(string name, params ResourceAccessLevel[] access) : Attribute
{
    /// <summary>
    /// Gets the name of the resource.
    /// </summary>
    public string Name { get; } = name;

    /// <summary>
    /// Gets the level of permission required to access the resource.
    /// </summary>
    public ResourceAccessLevel[] Access { get; } = access;
}

/// <summary>
/// Extension methods for the <see cref="ResourceAccessAttribute"/> class.
/// </summary>
public static class ResourceAccessAttributeExtensions
{
    /// <summary>
    /// Gets the name of the resource, falling back on data from the controller action descriptor.
    /// </summary>
    /// <param name="attribute">The attribute defining resource access requirements</param>
    /// <param name="descriptor">The descriptor providing info about the controller being accessed</param>
    /// <returns>The name of the resource.</returns>
    public static string GetResourceName(this ResourceAccessAttribute? attribute, ControllerActionDescriptor descriptor)
    {
        return attribute?.Name
            ?? descriptor.ControllerName;
    }

    /// <summary>
    /// Gets the list of access levels required to access the resource.
    /// </summary>
    /// <param name="attribute">The attribute defining resource access requirements</param>
    /// <param name="httpMethod">The HTTP method used to access the resource</param>
    /// <returns>The access level requirements.</returns>
    public static ResourceAccessLevel[] GetAccessLevels(this ResourceAccessAttribute? attribute, string httpMethod)
    {
        return attribute?.Access
            ?? ToAccessLevels(httpMethod);

        static ResourceAccessLevel[] ToAccessLevels(string httpMethod)
        {
            bool isReadOnly =
                HttpMethods.IsGet(httpMethod) ||
                HttpMethods.IsHead(httpMethod) ||
                HttpMethods.IsOptions(httpMethod) ||
                HttpMethods.IsTrace(httpMethod);

            return isReadOnly
                ? [ResourceAccessLevel.Admin, ResourceAccessLevel.Edit, ResourceAccessLevel.View]
                : [ResourceAccessLevel.Admin, ResourceAccessLevel.Edit];
        }
    }
}
