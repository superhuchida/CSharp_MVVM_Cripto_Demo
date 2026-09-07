using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureDeviceControl.Security
{
    public interface ISignatureService
    {
        byte[] Sign(byte[] data);

        bool Verify(byte[] data, byte[] signature);
    }
}
