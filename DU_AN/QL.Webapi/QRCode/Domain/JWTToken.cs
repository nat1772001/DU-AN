using System;

namespace QRCode.Domain
{
    public class JWTToken
    {
        public virtual int ID { get; set; }
        public virtual string Token { get; set; }
        public virtual DateTime ExpiredDate { get; set; }
        public virtual int ComId { get; set; }
        public virtual string UserName { get; set; }
    }
}
