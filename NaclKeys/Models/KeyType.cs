namespace NaclKeys.Models
{
    public enum KeyType
    {
        MiniLock = 0,
        CurveLock = 1,
        Bytejail = 2,
        // keep some space for further formats
        Unknown = 9,
        Invalid = 10
    }
}