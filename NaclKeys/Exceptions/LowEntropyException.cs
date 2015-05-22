using System;

namespace NaclKeys.Exceptions
{
    public class LowEntropyException : Exception
    {
        public LowEntropyException()
        {
        }

        public LowEntropyException(string message)
            : base(message)
        {
        }

        public LowEntropyException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}