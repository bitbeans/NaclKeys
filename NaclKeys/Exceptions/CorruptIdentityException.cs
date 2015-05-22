using System;

namespace NaclKeys.Exceptions
{
    public class CorruptIdentityException : Exception
    {
        public CorruptIdentityException()
        {
        }

        public CorruptIdentityException(string message)
            : base(message)
        {
        }

        public CorruptIdentityException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}