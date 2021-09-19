using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FX.Core;
using log4net;
using Microsoft.IdentityModel.Tokens;
using QRCode.Domain;
using QRCode.Service;

namespace QL.Webapi.Jwt
{
    public static class JwtManager
    {
        /// <summary>
        /// Use the below code to generate symmetric Secret Key
        ///     var hmac = new HMACSHA256();
        ///     var key = Convert.ToBase64String(hmac.Key);
        /// </summary>
        ///
        private const string Secret = "db3OIsj+BXE9NZDy0t8W3TcNekrF+2d/1sFnWG4HnV8TZY30iTOdtVWJG8abWvB1GlOgJuQZdcF2Luqm/hccMw==";

        private static ILog log = LogManager.GetLogger(typeof(JwtManager));

        private static object looker = new object();

        /// <summary>
        /// tạo jwt token
        /// nếu chưa có tạo mới vào db
        /// nếu có rồi thì ra hạn và update vào db
        /// </summary>
        /// <param name="comId"></param>
        /// <param name="username"></param>
        /// <param name="expireMinutes"></param>
        /// <returns></returns>
        public static string GenerateToken(int comId, string username, string[] roles, int expireMinutes = 20)
        {
            try
            {
                string token = null;
                var now = DateTime.UtcNow;
                var service = IoC.Resolve<IJWTTokenService>();
                //Kiếm tra token của user đã tồn tại trên hệ thống hay chưa
                //Nếu có rồi thì cập nhật với ID cũ
                //Nếu chưa có thì tạo mới 1 bản ghi

                JWTToken jWTToken = null;

                // synchronize
                //lock (looker)
                //{
                //    jWTToken = service.GetToken(comId, username);
                //}

                //if (jWTToken == null)
                //{
                //    tạo mới
                //    jWTToken = new JWTToken();
                //    jWTToken.ComId = comId;
                //    jWTToken.UserName = username.Trim().ToLower();
                //}

                //luôn luôn tạo token mới khi đăng nhập
                jWTToken = new JWTToken();
                jWTToken.ComId = comId;
                jWTToken.UserName = username.Trim().ToLower();

                // generate jwt token
                var symmetricKey = Convert.FromBase64String(Secret);
                var tokenHandler = new JwtSecurityTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Claims = new Dictionary<string, object>(),
                    Expires = now.AddMinutes(expireMinutes),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
                };

                tokenDescriptor.Claims.Add(ClaimTypes.Name, username);
                tokenDescriptor.Claims.Add(ClaimTypes.Role, roles);
                //if (roles != null)
                //{
                //    foreach (var role in roles)
                //    {
                //        tokenDescriptor.Claims.Add(ClaimTypes.Role, role);
                //    }
                //}

                tokenDescriptor.Claims.Add("ComId", comId);

                SecurityToken securityToken = tokenHandler.CreateToken(tokenDescriptor);
                token = tokenHandler.WriteToken(securityToken);

                // save token
                jWTToken.Token = token;
                jWTToken.ExpiredDate = securityToken.ValidTo;

                service.Save(jWTToken);
                service.CommitChanges();

                return token;
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return null;
            }
        }

        public static ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

                if (jwtToken == null)
                    return null;

                var symmetricKey = Convert.FromBase64String(Secret);

                var validationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                return principal;
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return null;
            }
        }
    }
}