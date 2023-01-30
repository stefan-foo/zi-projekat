using Cryptography.ServiceHost;
using Cryptography.ServiceHost.Utils;
using Grpc.Core;

namespace Cryptography.ServiceHost.Services
{
    public class CryptographyService : Cryptography.CryptographyBase
    {
        public override async Task OFBDecrypt(IAsyncStreamReader<OFBDecryptRequest> requestStream, IServerStreamWriter<OFBDecryptReply> responseStream, ServerCallContext context)
        {
            await requestStream.MoveNext();

            var ofb = new OFB(
                requestStream.Current.IV.ToByteArray(), 
                requestStream.Current.BlockCipherKey.ToByteArray());

            do
            {
                foreach (var block in ofb.Decrypt(requestStream.Current.EncryptedData.ToByteArray()))
                {
                    await responseStream.WriteAsync(new OFBDecryptReply
                    {
                        Data = Google.Protobuf.ByteString.CopyFrom(block)
                    });
                }
            } while (await requestStream.MoveNext());
        }
        public override async Task OFBEncrypt(IAsyncStreamReader<OFBEncryptRequest> requestStream, IServerStreamWriter<OFBEncryptReply> responseStream, ServerCallContext context)
        {
            await requestStream.MoveNext();

            var ofb = new OFB(
                requestStream.Current.IV.ToByteArray(),
                requestStream.Current.BlockCipherKey.ToByteArray());

            do
            {
                foreach (var block in ofb.Encrypt(requestStream.Current.Data.ToByteArray()))
                {
                    await responseStream.WriteAsync(new OFBEncryptReply
                    {
                        EncryptedData = Google.Protobuf.ByteString.CopyFrom(block)
                    });
                }
            } while (await requestStream.MoveNext());

            if (!ofb.Empty)
            {
                await responseStream.WriteAsync(new OFBEncryptReply
                {
                    EncryptedData = Google.Protobuf.ByteString.CopyFrom(ofb.EncryptRemaining())
                });
            }
        }
        public override async Task FSCDecrypt(IAsyncStreamReader<FSCDecryptRequest> requestStream, IServerStreamWriter<FSCDecryptReply> responseStream, ServerCallContext context)
        {
            try
            {
                await requestStream.MoveNext();

                var key1 = requestStream.Current.Key1;
                var key2 = requestStream.Current.Key2;

                var fsc = new FourSquareCypher(key1, key2);

                do
                {
                    await responseStream.WriteAsync(new FSCDecryptReply
                    {
                        Text = fsc.Decrypt(requestStream.Current.EncryptedText)
                    });
                } while (await requestStream.MoveNext());
            }
            catch (ArgumentException e)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, e.Message));
            }
        }
        public override async Task FSCEncrypt(IAsyncStreamReader<FSCEncryptRequest> requestStream, IServerStreamWriter<FSCEncryptReply> responseStream, ServerCallContext context)
        {
            try
            {
                await requestStream.MoveNext();

                var key1 = requestStream.Current.Key1;
                var key2 = requestStream.Current.Key2;

                var fsc = new FourSquareCypher(key1, key2);

                do
                {
                    await responseStream.WriteAsync(new FSCEncryptReply
                    {
                        EncryptedText = fsc.Encrypt(requestStream.Current.Text)
                    });
                } while (await requestStream.MoveNext());
            } catch (ArgumentException e)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, e.Message));
            }
        }
        public override async Task OTPDecrypt(IAsyncStreamReader<DecryptRequest> requestStream, IServerStreamWriter<DecryptReply> responseStream, ServerCallContext context)
        {
            while (await requestStream.MoveNext())
            {
                byte[] data = OneTimePad.Decrypt(
                    requestStream.Current.EncryptedData.ToByteArray(),
                    requestStream.Current.Key.ToByteArray(), 4);

                await responseStream.WriteAsync(new DecryptReply
                {
                    Data = Google.Protobuf.ByteString.CopyFrom(data)
                });
            }
        }
        public override async Task OTPEncrypt(IAsyncStreamReader<EncryptRequest> requestStream, IServerStreamWriter<EncryptReply> responseStream, ServerCallContext context)
        {
            while (await requestStream.MoveNext())
            {
                byte[] encryptedData = OneTimePad.Encrypt(
                    requestStream.Current.Data.ToByteArray(),
                    requestStream.Current.Key.ToByteArray(), 4);

                await responseStream.WriteAsync(new EncryptReply {
                    EncryptedData = Google.Protobuf.ByteString.CopyFrom(encryptedData)
                });
            }
        }
        public override async Task<SHA1HashReply> SHA1Hash(IAsyncStreamReader<SHA1HashRequest> requestStream, ServerCallContext context)
        {
            SHA1 sha = new();

            while (await requestStream.MoveNext() == true)
            {
                sha.HashBlock(requestStream.Current.Data.ToByteArray());
            }

            return new SHA1HashReply
            {
                Value = sha.Result()
            };
        }
        public override async Task<SHA1VerifyReply> SHA1Verify(IAsyncStreamReader<SHA1VerifyRequest> requestStream, ServerCallContext context)
        {
            SHA1 sha = new();

            await requestStream.MoveNext();

            if (requestStream.Current.PayloadCase != SHA1VerifyRequest.PayloadOneofCase.Hash)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Ocekivani inicijalni payload je hash za proveru"));
            }

            string hash = requestStream.Current.Hash;

            while (await requestStream.MoveNext())
            {
                sha.HashBlock(requestStream.Current.Data.ToByteArray());
            }

            return new SHA1VerifyReply
            {
                IsValid = sha.Verify(hash)
            };
        }
        public override async Task XXTEADecrypt(IAsyncStreamReader<DecryptRequest> requestStream, IServerStreamWriter<DecryptReply> responseStream, ServerCallContext context)
        {
            await requestStream.MoveNext();

            var xxtea = new XXTEAfbs(requestStream.Current.Key.ToByteArray());

            do
            {
                foreach (var block in xxtea.Decrypt(requestStream.Current.EncryptedData.ToByteArray()))
                {
                    await responseStream.WriteAsync(new DecryptReply
                    {
                        Data = Google.Protobuf.ByteString.CopyFrom(block)
                    });
                }
            } while (await requestStream.MoveNext());
        }
        public override async Task XXTEAEncrypt(IAsyncStreamReader<EncryptRequest> requestStream, IServerStreamWriter<EncryptReply> responseStream, ServerCallContext context)
        {
            await requestStream.MoveNext();

            var xxtea = new XXTEAfbs(requestStream.Current.Key.ToByteArray());
            do
            {
                foreach (var block in xxtea.Encrypt(requestStream.Current.Data.ToByteArray()))
                {
                    await responseStream.WriteAsync(new EncryptReply
                    {
                        EncryptedData = Google.Protobuf.ByteString.CopyFrom(block)
                    });
                }
            } while (await requestStream.MoveNext());

            if (!xxtea.Empty)
            {
                await responseStream.WriteAsync(new EncryptReply
                {
                    EncryptedData = Google.Protobuf.ByteString.CopyFrom(xxtea.EncryptRemaining())
                });
            }
        }
        public override async Task BMPEncrypt(IAsyncStreamReader<BMPEncryptRequest> requestStream, IServerStreamWriter<BMPEncryptReply> responseStream, ServerCallContext context)
        {
            var bmpEnc = new BMPEncryption();

            while (await requestStream.MoveNext())
            {
                var (encryptedBmp, key) = bmpEnc.Encrypt(requestStream.Current.Bmp.ToByteArray());
                await responseStream.WriteAsync(new BMPEncryptReply
                {
                    EncryptedBmp = Google.Protobuf.ByteString.CopyFrom(encryptedBmp),
                    Key = Google.Protobuf.ByteString.CopyFrom(key)
                });
            }
        }
        public override async Task BMPDecrypt(IAsyncStreamReader<BMPDecryptRequest> requestStream, IServerStreamWriter<BMPDecryptReply> responseStream, ServerCallContext context)
        {
            var bmpEnc = new BMPEncryption();

            while (await requestStream.MoveNext())
            {
                var bmpData = bmpEnc.Decrypt(
                    requestStream.Current.EncryptedBmp.ToByteArray(),
                    requestStream.Current.Key.ToByteArray());

                await responseStream.WriteAsync(new BMPDecryptReply
                {
                    Bmp = Google.Protobuf.ByteString.CopyFrom(bmpData)
                });
            }
        }
    }
}