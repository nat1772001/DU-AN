using FX.Common.IService;
using FX.Context;
using FX.Core;
using IdentityManagement.Authorization;
using log4net;
using QL.Webapi.Jwt;
using QL.Webapi.Models.Auth;
using QRCode.Service;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace QL.Webapi.Controllers
{
    [RoutePrefix("api/account")]
    public class AccountController : ApiController
    {
        private readonly ILog log = LogManager.GetLogger(typeof(AccountController));

        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public HttpResponseMessage Login(JWTTokenModel modelToken)
        {
            ICompanyService service = IoC.Resolve<ICompanyService>();
            var fxAuthen = IoC.Resolve<FanxiAuthenticationBase>(); ;
            try
            {
                string messages = "";
                if (!ModelState.IsValid)
                {
                    var mess = ModelState.Values.SelectMany(v => v.Errors);
                    return Request.CreateResponse(HttpStatusCode.BadRequest, mess.FirstOrDefault().ErrorMessage);
                }

                var company = service.Query.Where(x => x.Code == modelToken.TaxCode).FirstOrDefault();
                if (company == null)
                    return Request.CreateResponse(HttpStatusCode.BadRequest);
                var user = fxAuthen.Authenticate(company.id.ToString(), modelToken.UserName, modelToken.Password, out messages);
                if (user == null)
                    return Request.CreateResponse(HttpStatusCode.BadRequest);
                int expiresToken = Int32.Parse(ConfigurationManager.AppSettings.Get("ExpiredTimeToken"));
                var roles = user.Roles != null ? user.Roles.Select(x => x.name).ToArray() : null;
                var token = JwtManager.GenerateToken(company.id, modelToken.UserName, roles, expiresToken);
                return Request.CreateResponse(HttpStatusCode.OK, new JWTResult()
                {
                    accessToken = token,
                    refreshToken = "",
                    expiresIn = DateTime.Now.AddMinutes(expiresToken)
                });
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return Request.CreateResponse(HttpStatusCode.BadRequest);
            }
        }

        [JwtAuthentication()]
        [HttpGet]
        [Route("logout")]
        public HttpResponseMessage Logout()
        {
            try
            {
                var service = IoC.Resolve<IJWTTokenService>();
                int comId = int.Parse(FXContext.Current.CurrentUser.GroupName);
                var modelToken = service.GetToken(comId, FXContext.Current.CurrentUser.username);
                if (modelToken != null)
                {
                    service.Delete(modelToken);
                    service.CommitChanges();
                }
                return Request.CreateResponse(HttpStatusCode.OK);
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return Request.CreateResponse(HttpStatusCode.BadRequest);
            }
        }
    }
}
