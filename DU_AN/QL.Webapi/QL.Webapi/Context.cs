using FX.Common.IService;
using FX.Context;
using FX.Core;
using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace QL.Webapi
{
    public class Context : FXContext
    {
        private ILog log = LogManager.GetLogger(typeof(Context));

        public override ICompany CurrentCompany
        {
            get
            {
                if (HttpContext.Current.User != null && HttpContext.Current.User.Identity != null)
                {
                    // webapi
                    if (HttpContext.Current.User.Identity.IsAuthenticated && HttpContext.Current.User.Identity is ClaimsIdentity)
                    {
                        var identity = HttpContext.Current.User.Identity as ClaimsIdentity;
                        var comId = int.Parse(identity?.FindFirst("ComId")?.Value);
                        var userName = HttpContext.Current.User.Identity.Name;
                        var deviceId = identity?.FindFirst("DeviceId")?.Value;

                        var service = IoC.Resolve<ICompanyService>();
                        _CurrentCompany = service.Getbykey(comId);
                    }
                }

                return _CurrentCompany;
            }
        }

        public override FXUser CurrentUser
        {
            get
            {
                if (HttpContext.Current.User != null && HttpContext.Current.User.Identity != null)
                {
                    // webapi
                    if (HttpContext.Current.User.Identity.IsAuthenticated && HttpContext.Current.User.Identity is ClaimsIdentity)
                    {
                        var identity = HttpContext.Current.User.Identity as ClaimsIdentity;
                        var comId = int.Parse(identity?.FindFirst("ComId")?.Value);
                        var userName = HttpContext.Current.User.Identity.Name;
                        var deviceId = identity?.FindFirst("DeviceId")?.Value;

                        _CurrentUser = new FXUser()
                        {
                            GroupName = comId.ToString(),
                            username = userName,
                            DeviceId = deviceId
                        };
                    }
                }

                return _CurrentUser;
            }
        }
    }
}