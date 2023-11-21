//******************************************************************************************************
//  ApplicationRole.cs - Gbtc
//
//  Copyright © 2016, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the MIT License (MIT), the "License"; you may
//  not use this file except in compliance with the License. You may obtain a copy of the License at:
//
//      http://opensource.org/licenses/MIT
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  02/27/2016 - J. Ritchie Carroll
//       Generated original version of source code.
//  11/09/2023 - Lillian Gensolin
//       Converted code to .NET core.
//
//******************************************************************************************************

using System;
using System.ComponentModel.DataAnnotations;
using Gemstone.ComponentModel.DataAnnotations;
using Gemstone.Data.Model;
using Gemstone.Expressions.Model;

namespace Gemstone.Security.Model;

// TODO: Move lines 34-81 out of Gemstone Security. 
// original namespace GSF.Data.Model
/// <summary>
/// Defines an attribute that will allow setting GET function roles for a modeled table.
/// </summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
public sealed class GetRolesAttribute : Attribute
{
    /// <summary>
    /// Gets field name to use for property.
    /// </summary>
    public string Roles
    {
        get;
    }

    /// <summary>
    /// Creates a new <see cref="GetRolesAttribute"/>.
    /// </summary>
    /// <param name="roles">Comma separated string of roles allowed for GET functions.</param>
    public GetRolesAttribute(string roles)
    {
        Roles = roles;
    }
}

/// <summary>
/// Defines an attribute that will allow setting View only functions for a modeled table.
/// </summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
public sealed class ViewOnlyAttribute : Attribute
{
    /// <summary>
    /// Gets field name to use for property.
    /// </summary>
    public bool ViewOnly
    {
        get;
    }

    /// <summary>
    /// Creates a new <see cref="ViewOnlyAttribute"/>.
    /// </summary>
    public ViewOnlyAttribute()
    {
        ViewOnly = true;
    }
}

/// <summary>
/// Model for ApplicationRole table.
/// </summary>
[PrimaryLabel("Name")]
[GetRoles("Administrator")]
[ViewOnly]
public class ApplicationRole
{
    /// <summary>
    /// Unique application role ID field.
    /// </summary>
    [PrimaryKey(true)]
    public Guid ID { get; set; }

    /// <summary>
    /// Name field.
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Name { get; set; }

    /// <summary>
    /// Description field.
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// Node ID field.
    /// </summary>
    public Guid NodeID { get; set; }

    /// <summary>
    /// Created on field.
    /// </summary>
    [DefaultValueExpression("DateTime.UtcNow")]
    public DateTime CreatedOn { get; set; }

    /// <summary>
    /// Created by field.
    /// </summary>
    [Required]
    [StringLength(200)]
    [DefaultValueExpression("UserInfo.CurrentUserID")]
    public string CreatedBy { get; set; }

    /// <summary>
    /// Updated on field.
    /// </summary>
    [DefaultValueExpression("this.CreatedOn", EvaluationOrder = 1)]
    public DateTime UpdatedOn { get; set; }

    /// <summary>
    /// Updated by field.
    /// </summary>
    [Required]
    [StringLength(200)]
    [DefaultValueExpression("this.CreatedBy", EvaluationOrder = 1)]
    public string UpdatedBy { get; set; }
}
