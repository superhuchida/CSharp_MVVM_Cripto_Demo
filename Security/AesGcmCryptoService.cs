using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace SecureDeviceControl.Security
{
    public sealed class AesGcmCryptoService : ICryptoService
    {
        private readonly byte[] _key;

        public AesGcmCryptoService(byte[] key)
        {
            _key = key;
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using AesGcm aes = new(_key, 16);

            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag);

            byte[] result = new byte[
                nonce.Length +
                tag.Length +
                ciphertext.Length];

            Buffer.BlockCopy(
                nonce, 0,
                result, 0,
                nonce.Length);

            Buffer.BlockCopy(
                tag, 0,
                result, nonce.Length,
                tag.Length);

            Buffer.BlockCopy(
                ciphertext, 0,
                result,
                nonce.Length + tag.Length,
                ciphertext.Length);

            return result;
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            byte[] nonce = encrypted[..12];
            byte[] tag = encrypted[12..28];
            byte[] ciphertext = encrypted[28..];

            byte[] plaintext = new byte[ciphertext.Length];

            using AesGcm aes = new(_key, 16);

            aes.Decrypt(
                nonce,
                ciphertext,
                tag,
                plaintext);

            return plaintext;
        }
    }
}
