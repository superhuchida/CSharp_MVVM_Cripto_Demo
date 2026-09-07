using System.Configuration;
using System.Data;
using System;
using System.IO; // Added for file operations
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using SecureDeviceControl.Security;
using SecureDeviceControl.Services;
using SecureDeviceControl.ViewModels;

namespace SecureDeviceControl
{
    public partial class App : Application
    {
        private ServiceProvider? _serviceProvider;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            ServiceCollection services = new();

            // -------------------------------------------------
            // Device communication
            // -------------------------------------------------

            services.AddSingleton<IDeviceService>(
                new TcpDeviceService("127.0.0.1", 5000));


            // -------------------------------------------------
            // AES-GCM
            // -------------------------------------------------

            services.AddSingleton<ICryptoService>(
                new AesGcmCryptoService(SecurityKeys.AesKey));


            // -------------------------------------------------
            // ECDSA
            // -------------------------------------------------

            ECDsa ecdsa = ECDsa.Create();

            // Export ONLY the public key.
            // The private key stays inside the WPF application.
            byte[] publicKey =
                ecdsa.ExportSubjectPublicKeyInfo();

            string publicKeyBase64 =
                Convert.ToBase64String(publicKey);

            string publicKeyPath =
                Path.Combine(
                    Path.GetTempPath(),
                    "SecureDeviceControl.EcdsaPublicKey.txt");

            File.WriteAllText(
                publicKeyPath,
                publicKeyBase64);

            Console.WriteLine(
                $"ECDSA public key exported to: {publicKeyPath}");


            services.AddSingleton<ISignatureService>(
                new EcdsaSignatureService(ecdsa));


            // -------------------------------------------------
            // ViewModel
            // -------------------------------------------------

            services.AddTransient<MainViewModel>();


            // -------------------------------------------------
            // Main Window
            // -------------------------------------------------

            services.AddTransient<MainWindow>();


            // -------------------------------------------------
            // Build DI container
            // -------------------------------------------------

            _serviceProvider =
                services.BuildServiceProvider();


            MainWindow mainWindow =
                _serviceProvider.GetRequiredService<MainWindow>();

            mainWindow.Show();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _serviceProvider?.Dispose();

            base.OnExit(e);
        }
    }
}

/* 
 // First version of the application using dependency injection and MVVM pattern.

namespace SecureDeviceControl
{
    public partial class App : Application
    {
        private ServiceProvider? _serviceProvider;

        protected override void OnStartup(
            StartupEventArgs e)
        {
            base.OnStartup(e);

            ServiceCollection services = new();

            // -------------------------------------------------
            // Device communication
            // -------------------------------------------------

            services.AddSingleton<IDeviceService>(
                new TcpDeviceService("127.0.0.1", 5000));

            // -------------------------------------------------
            // AES-GCM
            // -------------------------------------------------

            byte[] aesKey = RandomNumberGenerator.GetBytes(32);

            services.AddSingleton<ICryptoService>(
             //  new AesGcmCryptoService(aesKey));
               new AesGcmCryptoService(SecurityKeys.AesKey));

            // -------------------------------------------------
            // ECDSA
            // -------------------------------------------------

            ECDsa ecdsa = ECDsa.Create();

            services.AddSingleton<ISignatureService>(
                new EcdsaSignatureService(ecdsa));

            // -------------------------------------------------
            // ViewModel
            // -------------------------------------------------

            services.AddTransient<MainViewModel>();

            // -------------------------------------------------
            // Main Window
            // -------------------------------------------------

            services.AddTransient<MainWindow>();

            // -------------------------------------------------
            // Build dependency injection container
            // -------------------------------------------------

            _serviceProvider = services.BuildServiceProvider();

            // -------------------------------------------------
            // Create and show MainWindow
            // -------------------------------------------------

            MainWindow mainWindow =
                _serviceProvider.GetRequiredService<MainWindow>();

            mainWindow.Show();
        }

        protected override void OnExit(
            ExitEventArgs e)
        {
            _serviceProvider?.Dispose();

            base.OnExit(e);
        }
    }
}
*/