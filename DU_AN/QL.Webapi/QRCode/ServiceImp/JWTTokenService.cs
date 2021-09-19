using FX.Data;
using QRCode.Domain;
using QRCode.Service;
using System.Linq;

namespace QRCode.ServiceImp
{
    public class JWTTokenService : BaseService<JWTToken, int>, IJWTTokenService
    {
        public JWTTokenService(string sessionFactoryConfigPath)
           : base(sessionFactoryConfigPath)
        { }

        public JWTToken GetDataByToken(string token)
        {
            return Query.Where(p => p.Token == token).FirstOrDefault();
        }

        public JWTToken GetToken(int comId, string userName)
        {
            return Query.Where(p => p.ComId == comId && p.UserName == userName).FirstOrDefault();
        }
    }
}
