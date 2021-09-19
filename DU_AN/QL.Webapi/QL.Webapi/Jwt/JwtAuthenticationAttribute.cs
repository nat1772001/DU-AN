using FX.Core;
using log4net;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Linq;
using IdentityManagement.Service;
using FX.Context.Security;
using QRCode.Service;

namespace QL.Webapi.Jwt
{
    public class JwtAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        private readonly ILog log = LogManager.GetLogger(typeof(JwtAuthenticationAttribute));

        string[] _Permissions;
        string[] _Roles;

        public string Permissions
        {
            get { return string.Join(",", _Permissions); }
            set { _Permissions = value.Split(','); }
        }

        public string Roles
        {
            get { return string.Join(",", _Roles); }
            set { _Roles = value.Split(','); }
        }

        public bool AllowMultiple => false;

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            try
            {
                var request = context.Request;
                var authorization = request.Headers.Authorization;

                if (authorization == null || authorization.Scheme != "Bearer")
                {
                    context.ErrorResult = new AuthenticationFailureResult("Invalid token", request);
                    return;
                }
                if (string.IsNullOrEmpty(authorization.Parameter))
                {
                    context.ErrorResult = new AuthenticationFailureResult("Missing Jwt Token", request);
                    return;
                }

                var token = authorization.Parameter;

                //check token có tồn tại trên hệ thống không
                var service = IoC.Resolve<IJWTTokenService>();
                var modelToken = service.GetDataByToken(token);
                if (modelToken == null)
                {
                    context.ErrorResult = new AuthenticationFailureResult("Invalid token", request);
                }
                else
                {
                    var principal = await AuthenticateJwtToken(token);
                    if (principal == null)
                    {
                        context.ErrorResult = new AuthenticationFailureResult("Invalid token", request);
                        //Nếu token hết hạn thì xóa token khỏi database
                        service.Delete(modelToken);
                        service.CommitChanges();
                    }
                    else
                        context.Principal = principal;
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            Challenge(context);
            return Task.FromResult(0);
        }

        private Task<IPrincipal> AuthenticateJwtToken(string token)
        {
            var principal = JwtManager.GetPrincipal(token);
            if (principal == null)
                return Task.FromResult<IPrincipal>(null);

            var identity = principal?.Identity as ClaimsIdentity;
            if (!identity.IsAuthenticated)
                Task.FromResult<IPrincipal>(null);

            var comId = identity?.FindFirst("ComId")?.Value;

            // check role & permission
            var roleService = IoC.Resolve<IroleService>();
            var roleClaims = identity?.FindAll(ClaimTypes.Role);
            var roleNames = roleClaims.Count() > 0 ? roleClaims.Select(x => x.Value).ToArray() : new string[0];
            var roles = new string[0];
            var permissions = new string[0];

            if (roleNames.Length > 0)
            {
                var fxRoles = roleService.Query.Where(x => x.GroupId == comId && roleNames.Contains(x.name)).ToArray();
                roles = fxRoles.Select(x => x.name).ToArray();
                permissions = fxRoles.SelectMany(x => x.Permissions.Select(p => p.name)).Distinct().ToArray();
            }

            if (_Roles != null && _Roles.Length > 0)
            {
                if (roles.Any(r => _Roles.Contains(r)))
                    return Task.FromResult((IPrincipal)principal);
            }
            else if (_Permissions != null && _Permissions.Length > 0)
            {
                if (permissions.Any(p => _Permissions.Contains(p)))
                    return Task.FromResult((IPrincipal)principal);
            }
            else
            {
                return Task.FromResult((IPrincipal)principal);
            }

            return Task.FromResult<IPrincipal>(null);
        }

        //private static bool ValidateToken(string token, out ClaimsPrincipal principal)
        //{
        //    string username = null;
        //    string roles = null;
        //    string deviceId = null;

        //    principal = JwtManager.GetPrincipal(token);
        //    var identity = principal?.Identity as ClaimsIdentity;

        //    if (identity == null)
        //        return false;

        //    if (!identity.IsAuthenticated)
        //        return false;

        //    var usernameClaim = identity.FindFirst(ClaimTypes.Name);
        //    username = usernameClaim?.Value;

        //    if (string.IsNullOrEmpty(username))
        //        return false;

        //    // More validate to check whether username exists in system
        //    var roleClaim = identity.FindFirst(ClaimTypes.Role);
        //    roles = roleClaim?.Value;

        //    var deviceClaim = identity.FindFirst("DeviceId");
        //    deviceId = deviceClaim?.Value;

        //    return true;
        //}

        private void Challenge(HttpAuthenticationChallengeContext context)
        {
            return;

            //string parameter = null;

            //if (!string.IsNullOrEmpty(Realm))
            //    parameter = "realm=\"" + Realm + "\"";

            //context.ChallengeWith("Bearer", parameter);
        }
    }
}