using System;
using System.ComponentModel.DataAnnotations;
using Gemstone.Expressions.Model;
using Gemstone.Data.Model;

namespace Gemstone.Security.Model
{
    public class AuthenticationProvider
    {
        [PrimaryKey(true)]
        public int ID { get; set; }

        public string ProviderIdentity { get; set; }

        public string Name { get; set; }

        public bool Enabled { get; set; }

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
    }

}
