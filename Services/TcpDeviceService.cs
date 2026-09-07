using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;

namespace SecureDeviceControl.Services
{
    public sealed class TcpDeviceService : IDeviceService
    {
        private readonly string _host;
        private readonly int _port;

        public TcpDeviceService(string host, int port)
        {
            _host = host;
            _port = port;
        }

        public async Task SendAsync(byte[] data)
        {
            using TcpClient client = new();

            await client.ConnectAsync(_host, _port);

            NetworkStream stream = client.GetStream();

            await stream.WriteAsync(data);
        }
    }
}
