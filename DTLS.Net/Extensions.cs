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
#if NET452 || NET47
        public static Task ConnectAsync(this Socket socket, EndPoint endpoint) =>
            Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, endpoint, null);
#endif

        public static Task<int> SendAsAsync(this Socket socket, byte[] buffer) =>
            Task.Factory.FromAsync(
                socket.BeginSend(buffer, 0, buffer.Length, SocketFlags.None, null, socket),
                socket.EndReceive
                );

        public static Task<int> ReceiveAsAsync(this Socket socket, byte[] buffer) =>
            Task.Factory.FromAsync(
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, null, socket),
                socket.EndReceive
                );

        public static async Task<TResult> TimeoutAfter<TResult>(this Task<TResult> task, int timeout, string message)
        {
            using (var timeoutCancellationTokenSource = new CancellationTokenSource())
            {
                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token));
                timeoutCancellationTokenSource.Cancel();
                if (completedTask == task)
                {
                    return await task;  // Very important in order to propagate exceptions
                }
                
                throw new OperationCanceledException(message);
            }
        }

        public static async Task TimeoutAfter(this Task task, int timeout, string message)
        {
            using (var timeoutCancellationTokenSource = new CancellationTokenSource())
            {
                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token));
                timeoutCancellationTokenSource.Cancel();
                if (completedTask == task)
                {
                    await task;  // Very important in order to propagate exceptions
                    return;
                }

                throw new OperationCanceledException(message);
            }
        }

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