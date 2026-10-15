using System;

namespace Fleck
{
    internal unsafe ref struct SpanWriter
    {
        private readonly Span<byte> _data;

        public int Length { get; private set; }

        public SpanWriter(Span<byte> data)
        {
            _data = data;
            Length = 0;
        }

        public void Write<T>(T value, bool reverse = true) where T : unmanaged
        {
            if (Length + sizeof(T) > _data.Length)
                throw new ArgumentException("Cannot write past end of span");

            var valueSpan = new Span<byte>(&value, sizeof(T));
            if (reverse) valueSpan.Reverse();
            var destSpan = _data.Slice(Length, sizeof(T));
            valueSpan.CopyTo(destSpan);
            Length += sizeof(T);
        }

        public void Write(ReadOnlySpan<byte> bytes)
        {
            if (Length + bytes.Length > _data.Length)
                throw new ArgumentException("Cannot write past end of span");

            bytes.CopyTo(_data.Slice(Length));
            Length += bytes.Length;
        }

        public void Write<T>(Span<T> values) where T : unmanaged
        {
            if (values.Length == 0)
                return; // nothing to write, and &values[0] below would throw

            var valuesLength = sizeof(T) * values.Length;
            if (Length + valuesLength > _data.Length)
                throw new ArgumentException("Cannot write past end of span");

            fixed (T* ptr = &values[0])
            {
                var valueSpan = new Span<byte>(ptr, valuesLength);
                var destSpan = _data.Slice(Length, valuesLength);
                valueSpan.CopyTo(destSpan);
                Length += valuesLength;
            }
        }
    }
}
