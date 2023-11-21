﻿//******************************************************************************************************
//  SecurityGroup.cs - Gbtc
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
using Gemstone.Identity;

namespace Gemstone.Security.Model;

/// <summary>
/// Model for SecurityGroup table.
/// </summary>
/// <remarks>
/// A record in this table can represent a database defined group with associated users
/// or an Active Directory group that maintains its own users.
/// </remarks>
[PrimaryLabel("Name")]
public class SecurityGroup
{
    /// <summary>
    /// Unique security group ID field.
    /// </summary>
    [PrimaryKey(true)]
    public Guid ID { get; set; }

    /// <summary>
    /// Group name field - stores SID for AD authentication.
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Name { get; set; }

    /// <summary>
    /// Description field.
    /// </summary>
    public string Description { get; set; }

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
    [UpdateValueExpression("DateTime.UtcNow")]
    public DateTime UpdatedOn { get; set; }

    /// <summary>
    /// Updated by field.
    /// </summary>
    [Required]
    [StringLength(200)]
    [DefaultValueExpression("this.CreatedBy", EvaluationOrder = 1)]
    [UpdateValueExpression("UserInfo.CurrentUserID")]
    public string UpdatedBy { get; set; }

    // TODO: Resolve issues with inability to resolve SIDToAccountName from Gemstone.Identity.UserInfo.
    ///// <summary>
    ///// Group account name, converted from security ID as needed.
    ///// </summary>
    //[NonRecordField]
    //public string AccountName => UserInfo.SIDToAccountName(Name);
}
