using System;

namespace NaclKeys.Exceptions
{
    public class InvalidMailException : Exception
    {
        public InvalidMailException()
        {
        }

        public InvalidMailException(string message)
            : base(message)
        {
        }

        public InvalidMailException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}