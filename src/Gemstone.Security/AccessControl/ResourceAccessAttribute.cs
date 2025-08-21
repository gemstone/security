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
/// Interface shared by <see cref="ResourceAccessAttribute"/>
/// and <see cref="NoResourceAccessAttribute"/>.
/// </summary>
public interface IResourceAccessAttribute
{
    /// <summary>
    /// Gets the name of the resource.
    /// </summary>
    string? Name { get; }

    /// <summary>
    /// Gets the type of permission required to access the resource.
    /// </summary>
    ResourceAccessType Access { get; }
}

/// <summary>
/// Annotation to assign an access type to an action on
/// a resource represented by a class, method, property, etc.
/// </summary>
/// <param name="name">The name of the resource</param>
/// <param name="access">The type of permission required to access the resource</param>
[AttributeUsage(AttributeTargets.All, Inherited = true, AllowMultiple = false)]
public class ResourceAccessAttribute(string? name, ResourceAccessType access) : Attribute, IResourceAccessAttribute
{
    /// <summary>
    /// Creates a new instance of the <see cref="ResourceAccessAttribute"/> class.
    /// </summary>
    /// <param name="access">The type of permission required to access the resource</param>
    public ResourceAccessAttribute(ResourceAccessType access)
        : this(null, access)
    {
    }

    /// <inheritdoc/>
    public string? Name { get; } = name;

    /// <inheritdoc/>
    public ResourceAccessType Access { get; } = access;
}

/// <summary>
/// Indicates that resource access logic does not apply
/// when attempting to access actions on a resource.
/// </summary>
[AttributeUsage(AttributeTargets.All, Inherited = true, AllowMultiple = false)]
public class NoResourceAccessAttribute() : Attribute, IResourceAccessAttribute
{
    string? IResourceAccessAttribute.Name => throw new NotSupportedException();
    ResourceAccessType IResourceAccessAttribute.Access => throw new NotSupportedException();
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
    public static string GetResourceName(this IResourceAccessAttribute? attribute, ControllerActionDescriptor descriptor)
    {
        return attribute?.Name
            ?? descriptor.ControllerName;
    }

    /// <summary>
    /// Gets the type of access required to access the resource.
    /// </summary>
    /// <param name="attribute">The attribute defining resource access requirements</param>
    /// <param name="httpMethod">The HTTP method used to access the resource</param>
    /// <returns>The access level requirements.</returns>
    public static ResourceAccessType? GetAccessType(this IResourceAccessAttribute? attribute, string httpMethod)
    {
        return attribute?.Access
            ?? ToAccessType(httpMethod);

        static ResourceAccessType? ToAccessType(string httpMethod)
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
            if (HttpMethods.IsDelete(httpMethod))
                return ResourceAccessType.Delete;
            return null;
        }
    }
}
