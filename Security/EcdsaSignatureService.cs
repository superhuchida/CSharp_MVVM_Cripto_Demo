using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureDeviceControl.Security
{
    public sealed class EcdsaSignatureService : ISignatureService
    {
        private readonly ECDsa _key;

        public EcdsaSignatureService(ECDsa key)
        {
            _key = key;
        }

        public byte[] Sign(byte[] data)
        {
            return _key.SignData(
                data,
                HashAlgorithmName.SHA256);
        }

        public bool Verify(byte[] data, byte[] signature)
        {
            return _key.VerifyData(
                data,
                signature,
                HashAlgorithmName.SHA256);
        }
    }
}
