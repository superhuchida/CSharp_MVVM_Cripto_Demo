using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using SecureDeviceControl.Security;
using SecureDeviceControl.Services;
using SecureDeviceControl.ViewModels;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecureDeviceControl.Tests.ViewModels
{
    public class MainViewModelTests
    {
        [Fact]
        public void Constructor_SetsInitialStatusToDisconnected()
        {
            // Arrange
            var deviceService = new FakeDeviceService();
            var cryptoService = new FakeCryptoService();
            var signatureService = new FakeSignatureService();

            // Act
            var viewModel = new MainViewModel(
                deviceService,
                cryptoService,
                signatureService);

            // Assert
            Assert.Equal("Disconnected", viewModel.Status);
        }

        [Fact]
        public void Speed_WhenChanged_RaisesPropertyChanged()
        {
            // Arrange
            var viewModel = CreateViewModel();

            string? changedProperty = null;

            viewModel.PropertyChanged += (_, e) =>
            {
                changedProperty = e.PropertyName;
            };

            // Act
            viewModel.Speed = 50;

            // Assert
            Assert.Equal(50, viewModel.Speed);
            Assert.Equal(nameof(viewModel.Speed), changedProperty);
        }

        [Fact]
        public void Speed_WhenSetToSameValue_DoesNotRaisePropertyChanged()
        {
            // Arrange
            var viewModel = CreateViewModel();

            viewModel.Speed = 50;

            int propertyChangedCount = 0;

            viewModel.PropertyChanged += (_, _) =>
            {
                propertyChangedCount++;
            };

            // Act
            viewModel.Speed = 50;

            // Assert
            Assert.Equal(0, propertyChangedCount);
        }

        [Fact]
        public async Task SendCommand_SendsSecurePacket()
        {
            // Arrange
            var deviceService = new FakeDeviceService();
            var cryptoService = new FakeCryptoService();
            var signatureService = new FakeSignatureService();

            var viewModel = new MainViewModel(
                deviceService,
                cryptoService,
                signatureService);

            viewModel.Speed = 75;

            // Act
            viewModel.SendCommand.Execute(null);

            await deviceService.SendCompleted.Task;

            // Assert
            Assert.NotNull(deviceService.SentData);

            string json = Encoding.UTF8.GetString(
                deviceService.SentData!);

            SecurePacket? packet =
                JsonSerializer.Deserialize<SecurePacket>(json);

            Assert.NotNull(packet);

            Assert.Equal(1, packet!.Version);
            Assert.Equal("SET_SPEED", packet.Command);

            Assert.False(string.IsNullOrWhiteSpace(packet.Nonce));
            Assert.False(string.IsNullOrWhiteSpace(packet.Tag));
            Assert.False(string.IsNullOrWhiteSpace(packet.Ciphertext));
            Assert.False(string.IsNullOrWhiteSpace(packet.Signature));

            Assert.Equal(
                "Secure command sent",
                viewModel.Status);
        }

        [Fact]
        public async Task SendCommand_CallsEncryptionAndSigning()
        {
            // Arrange
            var deviceService = new FakeDeviceService();
            var cryptoService = new FakeCryptoService();
            var signatureService = new FakeSignatureService();

            var viewModel = new MainViewModel(
                deviceService,
                cryptoService,
                signatureService);

            viewModel.Speed = 100;

            // Act
            viewModel.SendCommand.Execute(null);

            await deviceService.SendCompleted.Task;

            // Assert
            Assert.True(cryptoService.EncryptCalled);
            Assert.True(signatureService.SignCalled);

            Assert.Equal(
                "SET_SPEED 100",
                cryptoService.LastPlaintext);
        }

        [Fact]
        public async Task SendCommand_WhenDeviceServiceFails_SetsErrorStatus()
        {
            // Arrange
            var deviceService = new FakeDeviceService
            {
                ExceptionToThrow = new InvalidOperationException(
                    "Connection failed")
            };

            var cryptoService = new FakeCryptoService();
            var signatureService = new FakeSignatureService();

            var viewModel = new MainViewModel(
                deviceService,
                cryptoService,
                signatureService);

            // Act
            viewModel.SendCommand.Execute(null);

            await deviceService.SendCompleted.Task;

            // Assert
            Assert.Equal(
                "Error: Connection failed",
                viewModel.Status);
        }

        private static MainViewModel CreateViewModel()
        {
            return new MainViewModel(
                new FakeDeviceService(),
                new FakeCryptoService(),
                new FakeSignatureService());
        }
    }

    internal sealed class FakeDeviceService : IDeviceService
    {
        public byte[]? SentData { get; private set; }

        public Exception? ExceptionToThrow { get; set; }

        public TaskCompletionSource<bool> SendCompleted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task SendAsync(byte[] data)
        {
            if (ExceptionToThrow != null)
            {
                SendCompleted.SetResult(true);
                throw ExceptionToThrow;
            }

            SentData = data;

            SendCompleted.SetResult(true);

            await Task.CompletedTask;
        }
    }

    internal sealed class FakeCryptoService : ICryptoService
    {
        public bool EncryptCalled { get; private set; }

        public string? LastPlaintext { get; private set; }

        public byte[] Encrypt(byte[] plaintext)
        {
            EncryptCalled = true;

            LastPlaintext = Encoding.UTF8.GetString(plaintext);

            // MainViewModel expects:
            //
            // encrypted[0..12]   = Nonce
            // encrypted[12..28]  = Tag
            // encrypted[28..]    = Ciphertext
            //
            // Therefore we need at least 29 bytes.

            return new byte[]
            {
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29
            };
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class FakeSignatureService : ISignatureService
    {
        public bool SignCalled { get; private set; }

        public byte[] Sign(byte[] data)
        {
            SignCalled = true;

            return new byte[]
            {
                101, 102, 103, 104
            };
        }

        public bool Verify(byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }
    }
}

/* Initailize the unit test class for MainViewModelTests
namespace SecureDeviceControl.Tests.ViewModels
{
    internal class MainViewModelTests
    {
    }
}
*/