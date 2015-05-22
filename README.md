# NaclKeys [![Build status](https://img.shields.io/appveyor/ci/bitbeans/NaclKeys.svg?style=flat-square)](https://ci.appveyor.com/project/bitbeans/naclkeys)  [![License](http://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](https://github.com/bitbeans/NaclKeys/blob/master/LICENSE)
Small library to generate libsodium-net compatible KeyPair`s and encoded public keys based on predefined formats.

## Supported Formats

### CurveLock Format
Project: [CurveLock](https://github.com/adamcaudill/CurveLock)
#### Methods
```csharp
public static KeyPair GenerateCurveLockKeyPair(string email, string password)
```
```csharp
public static string EncodeCurveLockPublicKey(byte[] publicKey)
```
```csharp
public static byte[] DecodeCurveLockPublicKey(string encodedPublicKey)
```
#### Example
```csharp
const string email = "someone@example.com";
const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
var keyPair = KeyGenerator.GenerateCurveLockKeyPair(email, password);
var encodedPublicKey = KeyGenerator.EncodeCurveLockPublicKey(keyPair.PublicKey);
```
> NMgsvm7ytEHdGEuj9QEaoW7uH2tMQe9Ji2h9viw7kzFkgApVkH

### miniLock Format
Project: [miniLock](https://github.com/kaepora/miniLock)
#### Methods
```csharp
public static KeyPair GenerateMiniLockKeyPair(string email, string password)
```
```csharp
public static string EncodeMiniLockPublicKey(byte[] publicKey)
```
```csharp
public static byte[] DecodeMiniLockPublicKey(string encodedPublicKey)
```
#### Example
```csharp
const string email = "someone@example.com";
const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
var keyPair = KeyGenerator.GenerateMiniLockKeyPair(email, password);
var encodedPublicKey = KeyGenerator.EncodeMiniLockPublicKey(keyPair.PublicKey);
```
> Cz5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe

### bytejail Format
Project: [bytejail](https://bytejail.com)
#### Methods
```csharp
public static KeyPair GenerateBytejailKeyPair(string userInputPartOne, string userInputPartTwo)
```
```csharp
public static string EncodeBytejailPublicKey(byte[] publicKey)
```
```csharp
public static byte[] DecodeBytejailPublicKey(string encodedPublicKey)
```
#### Example
```csharp
const string email = "someone@example.com";
const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
var keyPair = KeyGenerator.GenerateBytejailKeyPair(email, password);
var encodedPublicKey = KeyGenerator.EncodeBytejailPublicKey(keyPair.PublicKey);
```
> 2PonPHk28TBvBu3iADjXZAH5gPh8fTpQ2mh4eMbkLhPnMrAywsq

##Helper
It`s also possible to recognize an identity format

```csharp
public static KeyType TryRecognizeIdentityFormat(string encodedPublicKey, bool validate = true)
```

## More Examples
see [Unit Tests](https://github.com/bitbeans/NaclKeys/tree/master/Tests)

## License
[MIT](https://en.wikipedia.org/wiki/MIT_License)