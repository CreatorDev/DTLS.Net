using System;
using System.Collections.Generic;
using System.Linq;

namespace DTLS.Net
{
    public static class Extensions
    {
        public static IEnumerable<IEnumerable<T>> ChunkBySize<T>(this IEnumerable<T> source, int size)
        {
            if(source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if(size <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }

            var results = new List<T>();
            using (var ie = source.GetEnumerator())
            {
                while (ie.MoveNext())
                {
                    results.Add(ie.Current);

                    if(results.Count >= size)
                    {
                        yield return results.ToArray();

                        results.Clear();
                    }
                }

                if (results.Any())
                {
                    yield return results.ToArray();
                }
            }
        }

        public static IEnumerable<T> GetRange<T>(this IEnumerable<T> source, int index, int count)
        {
            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }

            if (source.Count() - index < count)
            {
                throw new ArgumentOutOfRangeException("Source must be at least size index + count");
            }

            return source.Skip(index).Take(count);
        }

        public static void ForEach<T>(this IEnumerable<T> source, Action<T> action)
        {
            if(source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if(action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            foreach(var element in source)
            {
                action(element);
            }
        }
    }
}
