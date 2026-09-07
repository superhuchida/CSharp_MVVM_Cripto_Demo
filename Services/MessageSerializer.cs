using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureDeviceControl.Services
{
    public static class MessageSerializer
    {
        public static byte[] Serialize<T>(T value)
        {
            string json = JsonSerializer.Serialize(value);

            return Encoding.UTF8.GetBytes(json);
        }

        public static T Deserialize<T>(byte[] data)
        {
            string json = Encoding.UTF8.GetString(data);

            return JsonSerializer.Deserialize<T>(json)
                ?? throw new InvalidOperationException("Invalid message.");
        }
    }
}
