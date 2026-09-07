using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureDeviceControl.Security
{
    public sealed class SecurePacket
    {
        public int Version { get; set; } = 1;

        public string Command { get; set; } = string.Empty;

        public string Nonce { get; set; } = string.Empty;

        public string Ciphertext { get; set; } = string.Empty;

        public string Tag { get; set; } = string.Empty;

        public string Signature { get; set; } = string.Empty;
    }
}
