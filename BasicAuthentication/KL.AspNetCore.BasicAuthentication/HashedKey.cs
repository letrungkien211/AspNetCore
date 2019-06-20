using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace KL.AspNetCore.BasicAuthentication
{
    /// <summary>
    /// Hashed key
    /// </summary>
    public class HashedKey
    {
        /// <summary>
        /// Salt, randomly generated
        /// </summary>
        [Required]
        public string Salt { get; set; }

        /// <summary>
        /// Hashed value
        /// </summary>
        [Required]
        public string Hashed { get; set; }
    }
}
