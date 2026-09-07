using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureDeviceControl.Security
{
    public static class SecurityKeys
    {
        // DEVELOPMENT / SIMULATOR KEY ONLY.
        // Do NOT use a hard-coded key in production.
        public static readonly byte[] AesKey =
        {
                0x10, 0x21, 0x32, 0x43,
                0x54, 0x65, 0x76, 0x87,
                0x98, 0xA9, 0xBA, 0xCB,
                0xDC, 0xED, 0xFE, 0x0F,
                0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77, 0x88,
                0x99, 0xAA, 0xBB, 0xCC,
                0xDD, 0xEE, 0xFF, 0x00
        };
    }
}
