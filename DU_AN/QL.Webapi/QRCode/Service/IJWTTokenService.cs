using FX.Data;
using QRCode.Domain;

namespace QRCode.Service
{
    public interface IJWTTokenService : IBaseService<JWTToken, int>
    {
        JWTToken GetDataByToken(string token);

        JWTToken GetToken(int comId, string userName);
    }
}
