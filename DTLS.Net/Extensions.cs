using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
#if NET452 || NET47
using System.Net;
#endif

namespace DTLS.Net
{
    public static class Extensions
    {
        public static async Task<int> SendAsync(this Socket socket, byte[] buffer, TimeSpan timeout)
        {
            var timeoutMs = (int)timeout.TotalMilliseconds;
#if NETSTANDARD2_1
            using (var cts = new CancellationTokenSource())
            {
                cts.CancelAfter(timeoutMs);
                return await socket.SendAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
            }
#else
            return await Task.Factory.FromAsync(
                socket.BeginSend(buffer, 0, buffer.Length, SocketFlags.None, null, socket),
                socket.EndReceive
                ).TimeoutAfterAsync(timeoutMs)
                .ConfigureAwait(false);
#endif
        }

        public static async Task<int> ReceiveAsync(this Socket socket, byte[] buffer, TimeSpan timeout)
        {
            var timeoutMs = (int)timeout.TotalMilliseconds;
#if NETSTANDARD2_1
            using (var cts = new CancellationTokenSource())
            {
                cts.CancelAfter(timeoutMs);
                return await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
            }
#else
            return await Task.Factory.FromAsync(
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, null, socket),
                socket.EndReceive
                ).TimeoutAfterAsync(timeoutMs)
                .ConfigureAwait(false);
#endif
        }

#if !NETSTANDARD2_1
        public static async Task<TResult> TimeoutAfterAsync<TResult>(this Task<TResult> task, int timeout)
        {
            using (var timeoutCancellationTokenSource = new CancellationTokenSource())
            {
                using (var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token)).ConfigureAwait(false))
                {
                    timeoutCancellationTokenSource.Cancel();
                    if (completedTask == task)
                    {
                        return await task.ConfigureAwait(false);  // Very important in order to propagate exceptions
                    }

                    throw new TimeoutException();
                }
            }
        }
#endif

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