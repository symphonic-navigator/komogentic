// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;

namespace Komogentic.Server.Accounts;

/// <summary>
/// Keys derived from bearer secrets, and what is sealed under them (spec §5): HKDF-SHA256 for the keys and the lookups,
/// AES-256-GCM for the sealed values, laid out as <c>nonce (12) | ciphertext | tag (16)</c>. The context is the
/// associated data, so a sealed value can't be moved to another record or read as another kind. HKDF suffices for the
/// secrets here: each is 32 random bytes or more, nothing a person chose.
/// </summary>
internal static class Sealing
{
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    /// <summary>A key for <see cref="Seal"/>, derived from <paramref name="secret"/> for one purpose (<paramref name="label"/>).</summary>
    public static byte[] Derive(string secret, string label) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(secret), KeyBytes, info: Encoding.UTF8.GetBytes(label));

    /// <summary>What a record is found by without storing the secret: an HKDF output under its own label, so it is
    /// never a key that opens anything.</summary>
    public static byte[] Lookup(string secret, string label) => Derive(secret, label + "/lookup");

    public static byte[] Seal(byte[] key, byte[] plaintext, string context)
    {
        var output = new byte[NonceBytes + plaintext.Length + TagBytes];
        var nonce = output.AsSpan(0, NonceBytes);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagBytes);
        aes.Encrypt(nonce, plaintext, output.AsSpan(NonceBytes, plaintext.Length), output.AsSpan(NonceBytes + plaintext.Length), Encoding.UTF8.GetBytes(context));
        return output;
    }

    /// <summary>The plaintext; <see cref="CryptographicException"/> if the key, the context or a byte differs.</summary>
    public static byte[] Open(byte[] key, byte[] sealedValue, string context)
    {
        if (sealedValue.Length < NonceBytes + TagBytes) throw new CryptographicException("The sealed value is too short.");
        var length = sealedValue.Length - NonceBytes - TagBytes;
        var plaintext = new byte[length];
        using var aes = new AesGcm(key, TagBytes);
        aes.Decrypt(sealedValue.AsSpan(0, NonceBytes), sealedValue.AsSpan(NonceBytes, length), sealedValue.AsSpan(NonceBytes + length), plaintext, Encoding.UTF8.GetBytes(context));
        return plaintext;
    }
}
