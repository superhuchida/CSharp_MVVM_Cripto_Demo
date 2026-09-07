using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecureDeviceControl.DeviceSimulator
{
    internal class Program
    {
        private const int Port = 5000;

        private static readonly string PublicKeyPath =
            Path.Combine(
                Path.GetTempPath(),
                "SecureDeviceControl.EcdsaPublicKey.txt");


        static async Task Main(string[] args)
        {
            Console.WriteLine("======================================");
            Console.WriteLine(" Secure Device TCP Simulator");
            Console.WriteLine("======================================");
            Console.WriteLine();

            Console.WriteLine(
                $"ECDSA public key file:");
            Console.WriteLine(
                PublicKeyPath);
            Console.WriteLine();

            TcpListener listener = new(
                IPAddress.Loopback,
                Port);

            listener.Start();

            Console.WriteLine(
                $"Listening on 127.0.0.1:{Port}");

            Console.WriteLine(
                "Waiting for connection...");

            Console.WriteLine();

            while (true)
            {
                TcpClient client =
                    await listener.AcceptTcpClientAsync();

                Console.WriteLine(
                    "Client connected.");

                _ = HandleClientAsync(client);
            }
        }


        private static async Task HandleClientAsync(
            TcpClient client)
        {
            using (client)
            {
                NetworkStream stream =
                    client.GetStream();

                byte[] buffer =
                    new byte[8192];

                try
                {
                    int bytesRead =
                        await stream.ReadAsync(buffer);

                    if (bytesRead == 0)
                    {
                        Console.WriteLine(
                            "Client disconnected.");

                        return;
                    }


                    // -------------------------------------------------
                    // 1. Receive JSON
                    // -------------------------------------------------

                    string received =
                        Encoding.UTF8.GetString(
                            buffer,
                            0,
                            bytesRead);

                    Console.WriteLine(
                        "Secure packet received.");


                    // -------------------------------------------------
                    // 2. Deserialize JSON
                    // -------------------------------------------------

                    SecurePacket? packet =
                        JsonSerializer.Deserialize<SecurePacket>(
                            received);

                    if (packet == null)
                    {
                        Console.WriteLine(
                            "ERROR: Invalid secure packet.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    Console.WriteLine(
                        $"Version: {packet.Version}");

                    Console.WriteLine(
                        $"Command: {packet.Command}");


                    // -------------------------------------------------
                    // 3. Validate packet version
                    // -------------------------------------------------

                    if (packet.Version != 1)
                    {
                        Console.WriteLine(
                            "ERROR: Unsupported packet version.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    // -------------------------------------------------
                    // 4. Base64 decode
                    // -------------------------------------------------

                    byte[] nonce =
                        Convert.FromBase64String(
                            packet.Nonce);

                    byte[] ciphertext =
                        Convert.FromBase64String(
                            packet.Ciphertext);

                    byte[] tag =
                        Convert.FromBase64String(
                            packet.Tag);

                    byte[] signature =
                        Convert.FromBase64String(
                            packet.Signature);


                    Console.WriteLine();

                    Console.WriteLine(
                        $"Nonce: {nonce.Length} bytes");

                    Console.WriteLine(
                        $"Ciphertext: {ciphertext.Length} bytes");

                    Console.WriteLine(
                        $"Tag: {tag.Length} bytes");

                    Console.WriteLine(
                        $"Signature: {signature.Length} bytes");


                    // -------------------------------------------------
                    // 5. Validate AES-GCM sizes
                    // -------------------------------------------------

                    if (nonce.Length != 12)
                    {
                        Console.WriteLine(
                            "ERROR: Invalid nonce length.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }

                    if (tag.Length != 16)
                    {
                        Console.WriteLine(
                            "ERROR: Invalid authentication tag.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    // -------------------------------------------------
                    // 6. Reconstruct signed encrypted data
                    //
                    // WPF originally signs:
                    //
                    // nonce + tag + ciphertext
                    // -------------------------------------------------

                    byte[] encrypted =
                        new byte[
                            nonce.Length +
                            tag.Length +
                            ciphertext.Length];

                    Buffer.BlockCopy(
                        nonce,
                        0,
                        encrypted,
                        0,
                        nonce.Length);

                    Buffer.BlockCopy(
                        tag,
                        0,
                        encrypted,
                        nonce.Length,
                        tag.Length);

                    Buffer.BlockCopy(
                        ciphertext,
                        0,
                        encrypted,
                        nonce.Length + tag.Length,
                        ciphertext.Length);


                    // -------------------------------------------------
                    // 7. Load ECDSA public key
                    // -------------------------------------------------

                    if (!File.Exists(PublicKeyPath))
                    {
                        Console.WriteLine();
                        Console.WriteLine(
                            "ERROR: ECDSA public key file not found.");

                        Console.WriteLine(
                            "Start the WPF application first.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    string publicKeyBase64 =
                        File.ReadAllText(
                            PublicKeyPath).Trim();

                    byte[] publicKey =
                        Convert.FromBase64String(
                            publicKeyBase64);


                    // -------------------------------------------------
                    // 8. Verify ECDSA signature
                    // -------------------------------------------------

                    bool signatureValid;

                    using (ECDsa ecdsa =
                        ECDsa.Create())
                    {
                        ecdsa.ImportSubjectPublicKeyInfo(
                            publicKey,
                            out _);

                        signatureValid =
                            ecdsa.VerifyData(
                                encrypted,
                                signature,
                                HashAlgorithmName.SHA256);
                    }


                    Console.WriteLine();

                    if (!signatureValid)
                    {
                        Console.WriteLine(
                            "ECDSA signature: INVALID");

                        Console.WriteLine(
                            "Command rejected.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }

                    Console.WriteLine(
                        "ECDSA signature: VALID");


                    // -------------------------------------------------
                    // 9. AES-GCM decrypt
                    // -------------------------------------------------

                    byte[] plaintext =
                        new byte[ciphertext.Length];

                    try
                    {
                        using AesGcm aes =
                            new(
                                SecurityKeys.AesKey,
                                16);

                        aes.Decrypt(
                            nonce,
                            ciphertext,
                            tag,
                            plaintext);
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine(
                            "AES-GCM authentication: INVALID");

                        Console.WriteLine(
                            "Command rejected.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    Console.WriteLine(
                        "AES-GCM authentication: VALID");


                    // -------------------------------------------------
                    // 10. Decode plaintext command
                    // -------------------------------------------------

                    string decryptedCommand =
                        Encoding.UTF8.GetString(
                            plaintext);

                    Console.WriteLine();

                    Console.WriteLine(
                        $"Decrypted command: {decryptedCommand}");


                    // -------------------------------------------------
                    // 11. Validate command consistency
                    // -------------------------------------------------

                    string expectedCommand =
                        $"SET_SPEED {GetSpeedFromCommand(decryptedCommand)}"; // Extract speed value from decrypted command remove eventually trailing whitespace

                    if (!decryptedCommand.StartsWith(
                            "SET_SPEED ",
                            StringComparison.Ordinal))
                    {
                        Console.WriteLine(
                            "ERROR: Unsupported command.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    // Check that the JSON command header agrees
                    // with the authenticated/decrypted command.
                    if (packet.Command != "SET_SPEED")
                    {
                        Console.WriteLine(
                            "ERROR: Command header mismatch.");

                        await SendResponseAsync(
                            stream,
                            "ERROR");

                        return;
                    }


                    // -------------------------------------------------
                    // 12. Command accepted
                    // -------------------------------------------------

                    Console.WriteLine(
                        "Command accepted.");


                    // -------------------------------------------------
                    // 13. Send response
                    // -------------------------------------------------

                    await SendResponseAsync(
                        stream,
                        "OK");

                    Console.WriteLine(
                        "Sent: OK");

                    Console.WriteLine(
                        "Connection closed.");

                    Console.WriteLine();
                }
                catch (JsonException ex)
                {
                    Console.WriteLine(
                        $"JSON error: {ex.Message}");
                }
                catch (FormatException ex)
                {
                    Console.WriteLine(
                        $"Base64 error: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"Connection error: {ex.Message}");
                }
            }
        }


        private static async Task SendResponseAsync(
            NetworkStream stream,
            string response)
        {
            byte[] responseBytes =
                Encoding.UTF8.GetBytes(response);

            await stream.WriteAsync(
                responseBytes);
        }

        // remove this method if you don't need to extract speed value from the command the simulator doesn't need it
        // it is for demo purposes only to show how to extract the speed value from the command string
        private static string GetSpeedFromCommand(
            string command)
        {
            const string prefix = "SET_SPEED ";

            if (!command.StartsWith(
                    prefix,
                    StringComparison.Ordinal))
            {
                return string.Empty;
            }

            return command[prefix.Length..];
        }
    }
}

/* 
 // First , we create a TCP listener that listens for incoming connections on a specified port.
 // When a client connects, we handle the connection in a separate task. We read data from the client, 
 // print it to the console, and send back a simple "OK" response. 
 // If any exceptions occur during the connection handling, we catch them and print an error message. 
namespace SecureDeviceControl.DeviceSimulator
{
    internal class Program
    {
        private const int Port = 5000;
        static async Task Main(string[] args)
        {
            Console.WriteLine("======================================");
            Console.WriteLine(" Secure Device TCP Simulator");
            Console.WriteLine("======================================");
            Console.WriteLine();

            TcpListener listener = new(
                IPAddress.Loopback,
                Port);

            listener.Start();

            Console.WriteLine($"Listening on 127.0.0.1:{Port}");
            Console.WriteLine("Waiting for connection...");
            Console.WriteLine();

            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();

                Console.WriteLine("\nClient connected.");

                _ = HandleClientAsync(client);
            }
        }

        private static async Task HandleClientAsync(
            TcpClient client)
        {
            using (client)
            {
                NetworkStream stream = client.GetStream();

                byte[] buffer = new byte[4096];

                try 
                { 
                    int bytesRead = await stream.ReadAsync(buffer); 
                    if (bytesRead == 0) 
                    { 
                        Console.WriteLine("Client disconnected."); 
                        return; 
                    } 
                    string received = Encoding.UTF8.GetString(buffer, 0, bytesRead); 
                    Console.WriteLine($"Received: {received}"); 
                    string response = "OK"; 
                    byte[] responseBytes = Encoding.UTF8.GetBytes(response); 
                    await stream.WriteAsync(responseBytes); 
                    Console.WriteLine($"Sent: {response}"); 
                    Console.WriteLine("Connection closed."); 
                } 
                catch (Exception ex) 
                { 
                    Console.WriteLine($"Connection error: {ex.Message}"); 
                }
            }
        }
    }
}
*/