using Cryptography.ServiceHost;
using Grpc.Core;
using System.Text;
using static Cryptography.ServiceHost.Cryptography;

namespace Cryptography.Client.Utils
{
    public class CryptographyLib
    {
        private const int BufferSize = 4096;
        private readonly CryptographyClient _client;
        public CryptographyLib(CryptographyClient client)
        {
            _client = client;
        }
        public async Task EncryptBMP(string srcPath, string dstPath, string keyDstPath)
        {
            try
            {
                byte[] bmpBytes = File.ReadAllBytes(srcPath);

                var response = await _client.BMPEncryptAsync(new BMPEncryptRequest {
                    Bitmap = Google.Protobuf.ByteString.CopyFrom(bmpBytes)
                });

                File.WriteAllBytes(dstPath, response.EncryptedBitmap.ToByteArray());
                File.WriteAllBytes(keyDstPath, response.Key.ToByteArray());
            } catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
        public async Task DecryptBMP(string srcPath, string keyPath, string dstPath)
        {
            try
            {
                byte[] encryptedBytes = File.ReadAllBytes(srcPath);
                byte[] keyBytes = File.ReadAllBytes(keyPath);

                var response = await _client.BMPDecryptAsync(new BMPDecryptRequest { 
                    EncryptedBitmap = Google.Protobuf.ByteString.CopyFrom(encryptedBytes),
                    Key = Google.Protobuf.ByteString.CopyFrom(keyBytes)
                });

                File.WriteAllBytes(dstPath, response.Bitmap.ToByteArray());
            } catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
        public async Task OFBDecrypt(string srcPath, string iVPath, string dstPath, string key)
        {
            var encryptCall = _client.OFBDecrypt();

            var requestTask = Task.Run(async () =>
            {
                using FileStream fs = new(srcPath, FileMode.Open);
                using FileStream ivs = new(iVPath, FileMode.Open);

                byte[] buffer = new byte[BufferSize];
                byte[] iV = new byte[BufferSize];

                ivs.Read(iV, 0, BufferSize);

                int read;
                while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    await encryptCall.RequestStream.WriteAsync(new OFBDecryptRequest
                    {
                        EncryptedData = Google.Protobuf.ByteString.CopyFrom(buffer, 0, read),
                        BlockCipherKey = Google.Protobuf.ByteString.CopyFrom(System.Text.Encoding.UTF8.GetBytes(key)),
                        IV = Google.Protobuf.ByteString.CopyFrom(iV)
                    });
                }

                await encryptCall.RequestStream.CompleteAsync();

                fs.Close();
                ivs.Close();
            });

            await Task.Run(async () =>
            {
                using FileStream ds = new(dstPath, FileMode.OpenOrCreate);

                while (await encryptCall.ResponseStream.MoveNext())
                {
                    ds.Write(encryptCall.ResponseStream.Current.Data.ToByteArray());
                }

                ds.Close();
            });

            await requestTask;
        }
        public async Task OFBEncrypt(string srcPath, string iVPath, string dstPath, string key)
        {
            var encryptCall = _client.OFBEncrypt();

            var requestTask = Task.Run(async () =>
              {
                  using FileStream fs = new(srcPath, FileMode.Open);
                  using FileStream ivs = new(iVPath, FileMode.Open);

                  byte[] buffer = new byte[BufferSize];
                  byte[] iV = new byte[BufferSize];

                  ivs.Read(iV, 0, BufferSize);

                  int read;
                  while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                  {
                      await encryptCall.RequestStream.WriteAsync(new OFBEncryptRequest
                      {
                          Data = Google.Protobuf.ByteString.CopyFrom(buffer, 0, read),
                          BlockCipherKey = Google.Protobuf.ByteString.CopyFrom(System.Text.Encoding.UTF8.GetBytes(key)),
                          IV = Google.Protobuf.ByteString.CopyFrom(iV)
                      });
                  }

                  await encryptCall.RequestStream.CompleteAsync();

                  fs.Close();
                  ivs.Close();
              });

            await Task.Run(async () =>
            {
                using FileStream ds = new(dstPath, FileMode.OpenOrCreate);

                while (await encryptCall.ResponseStream.MoveNext())
                {
                    ds.Write(encryptCall.ResponseStream.Current.EncryptedData.ToByteArray());
                }

                ds.Close();
            });

            await requestTask;
        }
        public async Task FSCEncrypt(string filePath, string encryptedFilePath, string key1, string key2)
        {
            using var stream = File.OpenRead(filePath);
            using var outputStream = File.OpenWrite(encryptedFilePath);
            using var reader = new StreamReader(stream);
            using var outputWriter = new StreamWriter(outputStream);
            {
                char[] buffer = new char[BufferSize];
                int read;

                var encryptCall = _client.FSCEncrypt();

                while ((read = await reader.ReadBlockAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await encryptCall.RequestStream.WriteAsync(new FSCEncryptRequest
                    {
                        Text = new string(buffer, 0, read),
                        Key1 = key1,
                        Key2 = key2
                    });

                    await encryptCall.ResponseStream.MoveNext();

                    outputWriter.Write(encryptCall.ResponseStream.Current.EncryptedText);
                }

                await encryptCall.RequestStream.CompleteAsync();
            }
        }
        public async Task FSCDecrypt(string encryptedFilePath, string decryptedFilePath, string key1, string key2)
        {
            using var inputStream = File.OpenRead(encryptedFilePath);
            using var outputStream = File.OpenWrite(decryptedFilePath);
            using var inputReader = new StreamReader(inputStream);
            using var outputWriter = new StreamWriter(outputStream);
            {
                char[] buffer = new char[BufferSize];
                int read;

                var encryptCall = _client.FSCDecrypt();

                while ((read = await inputReader.ReadBlockAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await encryptCall.RequestStream.WriteAsync(new FSCDecryptRequest
                    {
                        EncryptedText = new string(buffer, 0, read),
                        Key1 = key1,
                        Key2 = key2
                    });

                    await encryptCall.ResponseStream.MoveNext();

                    outputWriter.Write(encryptCall.ResponseStream.Current.Text);
                }
            }
        }
        public async Task<string> SHA1HashFile(string path)
        {
            using FileStream fs = new(path, FileMode.Open);

            var sha1Call = _client.SHA1Hash();
            byte[] buffer = new byte[BufferSize];

            int read;
            while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                await sha1Call.RequestStream.WriteAsync(new SHA1HashRequest
                {
                    Data = Google.Protobuf.ByteString.CopyFrom(buffer, 0, read)
                });
            }

            await sha1Call.RequestStream.CompleteAsync();

            return (await sha1Call.ResponseAsync).Value;
        }
        public async Task<bool> SHA1VerifyFileHash(string path, string hash)
        {
            using FileStream fs = new(path, FileMode.Open);

            var sha1Call = _client.SHA1Verify();
            byte[] buffer = new byte[BufferSize];

            await sha1Call.RequestStream.WriteAsync(new SHA1VerifyRequest
            {
                Hash = hash
            });

            int read;
            while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                await sha1Call.RequestStream.WriteAsync(new SHA1VerifyRequest
                {
                    Data = Google.Protobuf.ByteString.CopyFrom(buffer, 0, read)
                });
            }

            await sha1Call.RequestStream.CompleteAsync();

            return (await sha1Call.ResponseAsync).IsValid;
        }
        public async Task OneTimePadDecrypt(string encryptedFilePath, string keyPath, string destPath)
        {
            FileStream fileStream = new(encryptedFilePath, FileMode.Open);
            FileStream destStream = new(destPath, FileMode.OpenOrCreate);
            FileStream keyStream = new(keyPath, FileMode.Open);

            if (keyStream.Length < fileStream.Length)
            {
                throw new ArgumentException("Kljuc mora biti vece ili jednake duzine od fajla koji se desifrira");
            }

            byte[] fileBuffer = new byte[4096];
            byte[] keyBuffer = new byte[4096];

            var encryptCall = _client.OTPDecrypt();

            int read;
            while ((read = fileStream.Read(fileBuffer, 0, fileBuffer.Length)) > 0)
            {
                keyStream.Read(keyBuffer, 0, keyBuffer.Length);

                await encryptCall.RequestStream.WriteAsync(new DecryptRequest
                {
                    EncryptedData = Google.Protobuf.ByteString.CopyFrom(fileBuffer, 0, read),
                    Key = Google.Protobuf.ByteString.CopyFrom(keyBuffer, 0, read)
                });

                await encryptCall.ResponseStream.MoveNext();

                destStream.Write(encryptCall.ResponseStream.Current.Data.ToByteArray());
            }

            await encryptCall.RequestStream.CompleteAsync();

            keyStream.Close();
            fileStream.Close();
            destStream.Close();
        }
        public async Task OneTimePadEncrypt(string filePath, string keyPath, string destPath)
        {
            FileStream keyStream = new(keyPath, FileMode.Open);
            FileStream fileStream = new(filePath, FileMode.Open);
            FileStream destStream = new(destPath, FileMode.OpenOrCreate);

            if (keyStream.Length < fileStream.Length)
            {
                throw new ArgumentException("Kljuc mora biti vece ili jednake duzine od fajla koji se sifrira");
            }

            byte[] fileBuffer = new byte[4096];
            byte[] keyBuffer = new byte[4096];

            var encryptCall = _client.OTPEncrypt();

            int read;
            while ((read = fileStream.Read(fileBuffer, 0, fileBuffer.Length)) > 0)
            {
                keyStream.Read(keyBuffer, 0, read);

                await encryptCall.RequestStream.WriteAsync(new EncryptRequest
                {
                    Data = Google.Protobuf.ByteString.CopyFrom(fileBuffer, 0, read),
                    Key = Google.Protobuf.ByteString.CopyFrom(keyBuffer, 0, read)
                });

                await encryptCall.ResponseStream.MoveNext();

                destStream.Write(encryptCall.ResponseStream.Current.EncryptedData.ToByteArray());
            }

            await encryptCall.RequestStream.CompleteAsync();

            keyStream.Close();
            fileStream.Close();
            destStream.Close();
        }
        public async Task XXTEAEncrypt(string srcPath, string dstPath, string key)
        {
            var encryptCall = _client.XXTEAEncrypt();

            var requestTask = Task.Run(async () =>
            {
                using FileStream fs = new(srcPath, FileMode.Open);

                byte[] buffer = new byte[BufferSize];

                int read;
                while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    await encryptCall.RequestStream.WriteAsync(new EncryptRequest
                    {
                        Data = Google.Protobuf.ByteString.CopyFrom(buffer, 0, read),
                        Key = Google.Protobuf.ByteString.CopyFrom(Encoding.UTF8.GetBytes(key))
                    });
                }

                await encryptCall.RequestStream.CompleteAsync();
            });

            await Task.Run(async () =>
            {
                using FileStream ds = new(dstPath, FileMode.OpenOrCreate);

                while (await encryptCall.ResponseStream.MoveNext())
                {
                    ds.Write(encryptCall.ResponseStream.Current.EncryptedData.ToByteArray());
                }
            });

            await requestTask;
        }
        public async Task XXTEADecrypt(string srcPath, string dstPath, string key)
        {
            var decryptCall = _client.XXTEADecrypt();

            var requestTask = Task.Run(async () =>
            {
                using FileStream fs = new(srcPath, FileMode.Open);

                byte[] buffer = new byte[BufferSize];

                int read;
                while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    await decryptCall.RequestStream.WriteAsync(new DecryptRequest
                    {
                        EncryptedData = Google.Protobuf.ByteString.CopyFrom(buffer, 0, read),
                        Key = Google.Protobuf.ByteString.CopyFrom(Encoding.UTF8.GetBytes(key))
                    });
                }

                await decryptCall.RequestStream.CompleteAsync();
            });

            await Task.Run(async () =>
            {
                using FileStream ds = new(dstPath, FileMode.OpenOrCreate);

                while (await decryptCall.ResponseStream.MoveNext())
                {
                    ds.Write(decryptCall.ResponseStream.Current.Data.ToByteArray());
                }
            });

            await requestTask;
        }
    }
}
