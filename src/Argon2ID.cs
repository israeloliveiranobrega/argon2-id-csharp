/*
Conhecer os outros é inteligência, conhecer-se a si próprio é verdadeira sabedoria
*/

using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Argon2ID;

/// <summary>
/// Provides cryptographic hashing and verification for passwords utilizing the Argon2id key derivation function.
/// </summary>
/// <param name="options">Configuration parameters dictating time, memory, and parallelism costs.</param>
public class Argon2ID(IOptions<Argon2IDOptions> options)
{
    private readonly Argon2IDOptions Options = options.Value;

    /// <summary>
    /// Secures a plaintext password by generating a salted and peppered Argon2id hash representation.
    /// </summary>
    /// <param name="rawPassword">The plaintext credential to be secured.</param>
    /// <returns>A formatted string containing the derivation parameters, salt, and resulting hash.</returns>
    public string Encrypt(string rawPassword)
    {
        byte[] saltGenerated = GenerateSalt();
        byte[] hashGenerated = GenerateHash(rawPassword + Options.Pepper, saltGenerated);

        string result = $"$argon2id" +
            $"$m={Options.MemoryCost}" +
            $"$t={Options.TimeCost}" +
            $"$p={Options.Parallelism}" +
            $"${EncodeUrlSafe(saltGenerated)}$" +
            $"{EncodeUrlSafe(hashGenerated)}";

        return result;
    }

    /// <summary>
    /// Evaluates a plaintext credential against an existing Argon2id formatted hash string.
    /// </summary>
    /// <param name="rawPassword">The plaintext credential submitted for evaluation.</param>
    /// <param name="hashPassword">The stored Argon2id formatted string containing the target hash and derivation parameters.</param>
    /// <returns>True if the computed hash matches the stored hash, otherwise false.</returns>
    public bool Verify(string rawPassword, string hashPassword)
    {
        Argon2IDHashSplit splitHash = SplitHash(hashPassword);

        byte[] hashBytes;

        using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(rawPassword + Options.Pepper)))
        {
            byte[] decodedSalt = DecodeUrlSafe(splitHash.Salt);

            argon2.Salt = decodedSalt;
            argon2.DegreeOfParallelism = splitHash.Parallelism;
            argon2.Iterations = splitHash.TimeCost;
            argon2.MemorySize = splitHash.MemoryCost;

            hashBytes = argon2.GetBytes(splitHash.HashSize);
        }

        byte[] decodedHash = DecodeUrlSafe(splitHash.Hash);

        bool result = CryptographicOperations.FixedTimeEquals(hashBytes, decodedHash);

        return result;
    }

    #region Generators

    /// <summary>
    /// Creates a cryptographically strong random sequence of bytes for use as a cryptographic salt.
    /// </summary>
    /// <returns>A byte array containing the generated salt.</returns>
    private byte[] GenerateSalt()
    {
        byte[] saltGenerated = new byte[Options.SaltSize];
        RandomNumberGenerator.Fill(saltGenerated);
        return saltGenerated;
    }

    /// <summary>
    /// Executes the core Argon2id algorithm to derive a cryptographic hash from the provided material.
    /// </summary>
    /// <param name="rawPassword">The combined plaintext credential and pepper.</param>
    /// <param name="salt">The cryptographic salt applied to the derivation process.</param>
    /// <returns>The raw derived cryptographic hash.</returns>
    private byte[] GenerateHash(string rawPassword, byte[] salt)
    {
        byte[] hashGenerated;

        using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(rawPassword)))
        {
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = Options.Parallelism;
            argon2.Iterations = Options.TimeCost;
            argon2.MemorySize = Options.MemoryCost;

            hashGenerated = argon2.GetBytes(Options.HashSize);
        }

        return hashGenerated;
    }

    /// <summary>
    /// Deconstructs the formatted hash string into its constituent derivation parameters and cryptographic payloads.
    /// </summary>
    /// <param name="hashPassword">The Argon2id formatted string.</param>
    /// <returns>An object encapsulating the extracted hashing parameters.</returns>
    private static Argon2IDHashSplit SplitHash(string hashPassword)
    {
        string[] slices = hashPassword.Split('$');

        var argonOptions = new Argon2IDHashSplit()
        {
            MemoryCost = int.Parse(slices[2].Split('=')[1]),
            TimeCost = int.Parse(slices[3].Split('=')[1]),
            Parallelism = int.Parse(slices[4].Split('=')[1]),
            Salt = slices[5],
            Hash = slices[6],
            HashSize = ExtractHashSize(slices[6])
        };

        return argonOptions;
    }

    #endregion

    #region Private Tools

    /// <summary>
    /// Determines the original byte length of a Base64 encoded payload.
    /// </summary>
    /// <param name="hash">The Base64 encoded string.</param>
    /// <returns>The size in bytes of the decoded payload.</returns>
    private static int ExtractHashSize(string hash)
    {
        int byteSize = Convert.FromBase64String(hash).Length;

        return byteSize;
    }

    /// <summary>
    /// Translates a raw byte array into a URL-safe Base64 encoded string format.
    /// </summary>
    /// <param name="buffer">The raw cryptographic material.</param>
    /// <returns>A URL-safe encoded string representation.</returns>
    private static string EncodeUrlSafe(byte[] buffer)
    {
        string hash = Convert.ToBase64String(buffer);
        string base64Hash = hash.Replace("+", "#").Replace("/", "-");
        return base64Hash;
    }

    /// <summary>
    /// Reconstructs a raw byte array from a URL-safe Base64 encoded string.
    /// </summary>
    /// <param name="base64Hash">The URL-safe encoded string.</param>
    /// <returns>The decoded raw cryptographic material.</returns>
    private static byte[] DecodeUrlSafe(string base64Hash)
    {
        string hash = base64Hash.Replace("#", "+").Replace("-", "/");
        return Convert.FromBase64String(hash);
    }

    #endregion
}