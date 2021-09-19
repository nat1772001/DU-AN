using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace QL.Webapi.Models.Auth
{
    public class JWTTokenModel
    {
        [Required(ErrorMessage = "UserName is required.")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; }

        [Required(ErrorMessage = "TaxCode is required.")]
        public string TaxCode { get; set; }
    }

    public class JWTResult
    {
        public string accessToken { get; set; }
        public string refreshToken { get; set; }
        public DateTime expiresIn { get; set; }
    }
}