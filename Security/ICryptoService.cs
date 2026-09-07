using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureDeviceControl.Security
{
    public interface ICryptoService
    {
        byte[] Encrypt(byte[] plaintext);

        byte[] Decrypt(byte[] encrypted);
    }
}
