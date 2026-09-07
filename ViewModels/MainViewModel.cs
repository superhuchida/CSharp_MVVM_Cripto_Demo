using SecureDeviceControl.Security;
using SecureDeviceControl.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;


namespace SecureDeviceControl.ViewModels
{
    public sealed class MainViewModel : INotifyPropertyChanged
    {
        private readonly IDeviceService _deviceService;
        private readonly ICryptoService _cryptoService;
        private readonly ISignatureService _signatureService;

        private int _speed;
        private string _status = "Disconnected";

        public MainViewModel(
            IDeviceService deviceService,
            ICryptoService cryptoService,
            ISignatureService signatureService)
        {
            _deviceService = deviceService;
            _cryptoService = cryptoService;
            _signatureService = signatureService;

            SendCommand = new RelayCommand(
                SendMotorCommand);
        }

        public int Speed
        {
            get => _speed;

            set
            {
                if (_speed == value)
                    return;

                _speed = value;

                OnPropertyChanged();
            }
        }

        public string Status
        {
            get => _status;

            private set
            {
                if (_status == value)
                    return;

                _status = value;

                OnPropertyChanged();
            }
        }

        public ICommand SendCommand { get; }
        /*
                private async void SendMotorCommand()
                {
                    try
                    {
                        Status = "Sending...";

                        string message = $"SET_SPEED {Speed}";

                        byte[] data = Encoding.UTF8.GetBytes(message);

                        await _deviceService.SendAsync(data);

                        Status = "Command sent";
                    }
                    catch (Exception ex)
                    {
                        Status = $"Error: {ex.Message}";
                    }
                }
        */

        private async void SendMotorCommand()
        {
            try
            {
                Status = "Encrypting...";

    // -------------------------------------------------
    // 1. Create the command
    // -------------------------------------------------

                string command = $"SET_SPEED {Speed}";

                byte[] plaintext =
                    Encoding.UTF8.GetBytes(command);

                // -------------------------------------------------
                // 2. Encrypt with AES-GCM
                // -------------------------------------------------

                byte[] encrypted =
                    _cryptoService.Encrypt(plaintext);

                // -------------------------------------------------
                // 3. Sign the encrypted data with ECDSA
                // -------------------------------------------------

                byte[] signature =
                    _signatureService.Sign(encrypted);

                // -------------------------------------------------
                // 4. Build secure packet
                // -------------------------------------------------

                SecurePacket packet = new()
                {
                    Version = 1,

                    Command = "SET_SPEED",

                    Nonce = Convert.ToBase64String(
                        encrypted[..12]),

                    Tag = Convert.ToBase64String(
                        encrypted[12..28]),

                    Ciphertext = Convert.ToBase64String(
                        encrypted[28..]),

                    Signature = Convert.ToBase64String(
                        signature)
                };

                // -------------------------------------------------
                // 5. Serialize packet
                // -------------------------------------------------

                string json =
                    JsonSerializer.Serialize(packet);

                byte[] packetBytes =
                    Encoding.UTF8.GetBytes(json);

                // -------------------------------------------------
                // 6. Send secure packet over TCP
                // -------------------------------------------------

                Status = "Sending secure command...";

                await _deviceService.SendAsync(packetBytes);

                Status = "Secure command sent";
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
            }
}


        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged(
            [CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(
                this,
                new PropertyChangedEventArgs(name));
        }
    }
}
