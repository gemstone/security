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
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Gemstone.Security.AccessControl;

/// <summary>
/// Annotation to assign an access type to an action on
/// a resource represented by a class, method, property, etc.
/// </summary>
[AttributeUsage(AttributeTargets.All, Inherited = true, AllowMultiple = false)]
public class ResourceAccessAttribute : Attribute
{
    private struct PrivateTag { }

    /// <summary>
    /// Creates a new instance of the <see cref="ResourceAccessAttribute"/> class.
    /// </summary>
    /// <param name="name">The name of the resource</param>
    public ResourceAccessAttribute(string name)
        : this(new(), name, ResourceAccessType.NotSpecified)
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="ResourceAccessAttribute"/> class.
    /// </summary>
    /// <param name="access">The type of permission required to access the resource</param>
    public ResourceAccessAttribute(ResourceAccessType access)
        : this(new(), null, access)
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="ResourceAccessAttribute"/> class.
    /// </summary>
    /// <param name="name">The name of the resource</param>
    /// <param name="access">The type of permission required to access the resource</param>
    public ResourceAccessAttribute(string name, ResourceAccessType access)
        : this(new(), name, access)
    {
    }

    private ResourceAccessAttribute(PrivateTag _, string? name, ResourceAccessType access)
    {
        Name = name;
        Access = access;
    }

    /// <inheritdoc/>
    public string? Name { get; }

    /// <inheritdoc/>
    public ResourceAccessType Access { get; }
}

/// <summary>
/// Extension methods for the <see cref="ResourceAccessAttribute"/> class.
/// </summary>
public static class ResourceAccessAttributeExtensions
{
    /// <summary>
    /// Gets the name of the resource, falling back on data from the controller action descriptor.
    /// </summary>
    /// <param name="attributes">The list of attributes defining resource access requirements in ascending order of precedence</param>
    /// <param name="descriptor">The descriptor providing info about the controller being accessed</param>
    /// <returns>The name of the resource.</returns>
    public static string GetResourceName(this IEnumerable<ResourceAccessAttribute> attributes, ControllerActionDescriptor descriptor)
    {
        return attributes
            .Select(attribute => attribute.Name)
            .Where(name => name is not null)
            .LastOrDefault() ?? descriptor.ControllerName;
    }

    /// <summary>
    /// Gets the type of access required to access the resource.
    /// </summary>
    /// <param name="attributes">The list of attributes defining resource access requirements in ascending order of precedence</param>
    /// <param name="httpMethod">The HTTP method used to access the resource</param>
    /// <returns>The access level requirements.</returns>
    /// <remarks>
    /// This method will never return <see cref="ResourceAccessType.NotSpecified"/> or <see cref="ResourceAccessType.Default"/>.
    /// If no access type is explicitly specified by any <see cref="ResourceAccessAttribute"/>,
    /// or if <see cref="ResourceAccessType.Default"/> is explicitly specified,
    /// then it will determine the appropriate level of access based on the <paramref name="httpMethod"/>.
    /// </remarks>
    public static ResourceAccessType GetAccessType(this IEnumerable<ResourceAccessAttribute> attributes, string httpMethod)
    {
        ResourceAccessType access = attributes.GetAccessType();

        return access == ResourceAccessType.Default
            ? ToAccessType(httpMethod)
            : access;

        static ResourceAccessType ToAccessType(string httpMethod)
        {
            if (HttpMethods.IsPost(httpMethod))
                return ResourceAccessType.Create;
            if (HttpMethods.IsGet(httpMethod))
                return ResourceAccessType.Read;
            if (HttpMethods.IsHead(httpMethod))
                return ResourceAccessType.Read;
            if (HttpMethods.IsOptions(httpMethod))
                return ResourceAccessType.Read;
            if (HttpMethods.IsTrace(httpMethod))
                return ResourceAccessType.Read;
            if (HttpMethods.IsPut(httpMethod))
                return ResourceAccessType.Update;
            if (HttpMethods.IsPatch(httpMethod))
                return ResourceAccessType.Update;
            if (HttpMethods.IsDelete(httpMethod))
                return ResourceAccessType.Delete;
            return ResourceAccessType.None;
        }
    }

    /// <summary>
    /// Gets the type of access required to access the resource.
    /// </summary>
    /// <param name="attributes">The list of attributes defining resource access requirements in ascending order of precedence</param>
    /// <returns>The access level requirements.</returns>
    /// <remarks>
    /// This method will never return <see cref="ResourceAccessType.NotSpecified"/>.
    /// If no access type is explicitly specified by any <see cref="ResourceAccessAttribute"/>,
    /// then it will return <see cref="ResourceAccessType.Default"/> instead.
    /// </remarks>
    public static ResourceAccessType GetAccessType(this IEnumerable<ResourceAccessAttribute> attributes)
    {
        return attributes
            .Select(attribute => attribute.Access)
            .Where(access => access != ResourceAccessType.NotSpecified)
            .DefaultIfEmpty(ResourceAccessType.Default)
            .Last();
    }
}
