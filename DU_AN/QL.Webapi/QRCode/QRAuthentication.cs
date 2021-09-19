using FX.Common.IService;
using FX.Context;
using FX.Context.Security;
using FX.Core;
using IdentityManagement;
using IdentityManagement.Authorization;
using IdentityManagement.Domain;
using IdentityManagement.Service;
using log4net;
using System;
using System.Linq;

namespace IdentityManagement.Authorization
{
    public class QRAuthentication : FanxiAuthenticationBase
    {
        static ILog log = LogManager.GetLogger(typeof(QRAuthentication));

        public override FXUserIdentity Authenticate(string mUserName, string mPassword)
        {
            try
            {
                var company = FXContext.Current.CurrentCompany;
                if (company == null) return null;
                return Authenticate(company.id.ToString(), mUserName, mPassword);
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return null;
            }
        }

        public override FXUserIdentity Authenticate(string groupName, string mUserName, string mPassword)
        {
            try
            {
                ICompanyService service = IoC.Resolve<ICompanyService>();
                var company = service.Getbykey(int.Parse(groupName));
                if (company == null) return null;
                IuserService userService = IoC.Resolve<IuserService>();
                user tempUser = userService.GetbyUserId(mUserName, company.id.ToString());
                if (tempUser == null) return null;
                string passHash = GeneratorPassword.EncodePassword(mPassword, tempUser.PasswordFormat, tempUser.PasswordSalt);
                if (tempUser.password != passHash)
                    return null;
                return new FXUserIdentity(tempUser, tempUser.Roles.ToList());
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return null;
            }
        }
        public override FXUserIdentity Authenticate(string groupName, string mUserName, string mPassword, out string messages)
        {
            messages = "";
            try
            {
                ICompanyService service = IoC.Resolve<ICompanyService>();
                var company = service.Getbykey(int.Parse(groupName));
                if (company == null)
                {
                    messages = "ERR_0";
                    return null;
                }
                IuserService userService = IoC.Resolve<IuserService>();
                user tempUser = userService.GetbyUserId(mUserName, company.id.ToString());
                if (tempUser == null)
                {
                    messages = "ERR_3";
                    return null;
                }
                if (!tempUser.IsApproved)
                {
                    messages = "ERR_4";
                    return null;
                }
                string passHash = GeneratorPassword.EncodePassword(mPassword, tempUser.PasswordFormat, tempUser.PasswordSalt);
                if (tempUser.password != passHash)
                {
                    messages = "ERR_3";
                    return null;
                }
                return new FXUserIdentity(tempUser, tempUser.Roles.ToList());
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return null;
            }
        }
    }
}
