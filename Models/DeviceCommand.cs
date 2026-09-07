using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureDeviceControl.Models
{
    public sealed class DeviceCommand
    {
        public string Command { get; set; } = "";

        public int Value { get; set; }
    }
}
